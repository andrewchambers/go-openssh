package openssh

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andrewchambers/go-errors"
)

type HostKeyAddress struct {
	Hostname string
	Port     uint16
}

func (hk *HostKeyAddress) String() string {
	if hk.Port != 22 {
		return fmt.Sprintf("[%s]:%d", hk.Hostname, hk.Port)
	}
	return hk.Hostname
}

// HostKey represents a line in a known hosts file
type HostKey struct {
	Addresses []HostKeyAddress
	KeyType   string
	KeyData   string
}

type KnownHosts struct {
	HostKeys []HostKey
}

func (knownHosts *KnownHosts) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	for _, k := range knownHosts.HostKeys {
		hasPrev := false
		for _, a := range k.Addresses {
			if hasPrev {
				_, _ = buf.WriteString(",")
			}
			_, _ = buf.WriteString(a.String())
		}
		buf.WriteString(fmt.Sprintf(" %s %s\n", k.KeyType, k.KeyData))
	}

	return buf.Bytes()
}

func ParseHostKeys(input []byte) ([]HostKey, error) {
	hostKeys := []HostKey{}

	r := bytes.NewBuffer(input)

	for {
		l, err := r.ReadString('\n')

		if strings.HasSuffix(l, "\n") {
			l = l[0 : len(l)-1]
		}

		malformedErr := func() error { return fmt.Errorf("malformed line: '%s'", l) }

		if len(l) != 0 && l[0] != '#' {
			parts := strings.Split(l, " ")
			if len(parts) != 3 && len(parts) != 4 {
				return nil, malformedErr()
			}

			k := HostKey{
				KeyType: parts[1],
				KeyData: parts[2],
			}

			hosts := strings.Split(parts[0], ",")
			for _, h := range hosts {
				if !strings.HasPrefix(h, "[") {
					k.Addresses = append(k.Addresses, HostKeyAddress{
						Hostname: h,
						Port:     22,
					})
					continue
				}

				st := 0
				hostNameBuf := bytes.NewBuffer(nil)
				portBuf := bytes.NewBuffer(nil)

				for _, c := range h {
					switch st {
					case 0:
						if c != '[' {
							return nil, malformedErr()
						}
						st = 1
					case 1:
						if c == ']' {
							st = 2
						} else {
							_, _ = hostNameBuf.WriteRune(c)
						}
					case 2:
						if c != ':' {
							return nil, malformedErr()
						}
						st = 3
					case 3:
						_, _ = portBuf.WriteRune(c)
					}
				}

				if st != 3 {
					return nil, malformedErr()
				}

				p, err := strconv.ParseUint(portBuf.String(), 10, 16)
				if err != nil {
					return nil, malformedErr()
				}

				k.Addresses = append(k.Addresses, HostKeyAddress{
					Hostname: hostNameBuf.String(),
					Port:     uint16(p),
				})
			}

			hostKeys = append(hostKeys, k)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}
	}

	return hostKeys, nil
}

type Config struct {
	Identity   Identity
	KnownHosts KnownHosts
}

type Identity struct {
	PublicKey  string
	PrivateKey string
}

func (config *Config) BuildSandbox() (*Sandbox, error) {
	dir, err := ioutil.TempDir("", "ssh-sandbox")
	if err != nil {
		return nil, err
	}

	knownHostsFilePath := filepath.Join(dir, "known_hosts")
	privateKeyFilePath := filepath.Join(dir, "id")
	publicKeyFilePath := privateKeyFilePath + ".pub"
	sshConfigFilePath := filepath.Join(dir, "ssh_config")

	sshConfigContents := fmt.Sprintf(`UserKnownHostsFile "%s"
IdentityFile "%s"
StrictHostKeyChecking yes
`, knownHostsFilePath, privateKeyFilePath)

	err = ioutil.WriteFile(knownHostsFilePath, config.KnownHosts.Bytes(), 0600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	err = ioutil.WriteFile(privateKeyFilePath, []byte(config.Identity.PrivateKey), 0600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	err = ioutil.WriteFile(publicKeyFilePath, []byte(config.Identity.PublicKey), 0600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	err = ioutil.WriteFile(sshConfigFilePath, []byte(sshConfigContents), 0600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	return &Sandbox{
		Dir: dir,

		KnownHostsFilePath: knownHostsFilePath,
		PrivateKeyFilePath: privateKeyFilePath,
		SSHConfigFilePath:  sshConfigFilePath,
	}, nil
}

// A sandbox is an ssh known hosts file, ssh key and a private key
// in a temporary directory, it allows you to execute openssh commands.
type Sandbox struct {
	Dir string

	KnownHostsFilePath string
	PrivateKeyFilePath string
	SSHConfigFilePath  string
}

func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	exitErr, ok := errors.RootCause(err).(*exec.ExitError)
	if ok {
		procStatus, ok := exitErr.Sys().(syscall.WaitStatus)
		if ok {
			return procStatus.ExitStatus()
		}
	}

	return 256
}

// Run script on the remote host. Returns rc == 256  and err != nil
// if there was an error setting up to run the script.
// returns rc == 255 and err == nil if there was an ssh error running the script.
// return rc == exitof(script) and err == nil if the script was run.
func (sbox *Sandbox) RunScriptOnHost(ctx context.Context, username string, ipAddress string, port uint16, stderrFn func(string), script string, extraArgs ...string) (int, error) {
	// XXX umask?
	cmd := sbox.GetSSHCommandForHost(ctx, username, ipAddress, port, "mktemp")
	mktempOutput, err := cmd.Output()
	if err != nil {
		return 256, errors.Wrap(err, "unable to create temp dir")
	}
	rPath := strings.Trim(string(mktempOutput), "\n")

	defer func() {
		ctx, _ := context.WithTimeout(ctx, 10*time.Second)
		cmd := sbox.GetSSHCommandForHost(ctx, username, ipAddress, port, "rm", rPath)
		_ = cmd.Run()
	}()

	f, err := ioutil.TempFile("", "")
	if err != nil {
		return 256, errors.Wrap(err, "unable to create temp dir")
	}
	defer os.Remove(f.Name())

	_, err = f.Write([]byte(script))
	if err != nil {
		return 256, errors.Wrap(err, "unable to write script")
	}

	err = f.Close()
	if err != nil {
		return 256, errors.Wrap(err, "unable to write script")
	}

	cmd = sbox.GetSCPCommand(ctx, "-P", fmt.Sprintf("%d", port), f.Name(), fmt.Sprintf("%s@%s:%s", username, ipAddress, rPath))
	err = cmd.Run()
	if err != nil {
		return 256, errors.Wrap(err, "upload script")
	}

	cmd = sbox.GetSSHCommandForHost(ctx, username, ipAddress, port, "chmod", "+x", rPath)
	err = cmd.Run()
	if err != nil {
		return 256, errors.Wrap(err, "unable to make script executable")
	}
	args := []string{rPath}
	args = append(args, extraArgs...)

	cmd = sbox.GetSSHCommandForHost(ctx, username, ipAddress, port, args...)
	a, b := io.Pipe()
	cmd.Stderr = b

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		wg.Done()
		output := bufio.NewReader(a)
		for {
			// XXX long lines could clog memory...
			// TODO
			ln, err := output.ReadString('\n')
			stderrFn(ln)
			if err != nil {
				break
			}
		}
	}()

	err = cmd.Run()
	wg.Wait()
	rc := getExitCode(err)
	if err != nil {
		if rc > 255 {
			return getExitCode(err), errors.Wrap(err, "error running script on remote")
		}
	}

	return rc, nil
}

func (sbox *Sandbox) GetSSHCommandForHost(ctx context.Context, username string, ipaddress string, port uint16, extraArgs ...string) *exec.Cmd {
	args := []string{}
	args = append(args, "-F")
	args = append(args, sbox.SSHConfigFilePath)
	args = append(args, "-p")
	args = append(args, fmt.Sprintf("%d", port))
	args = append(args, fmt.Sprintf("%s@%s", username, ipaddress))
	args = append(args, extraArgs...)
	return exec.CommandContext(ctx, "ssh", args...)
}

func (sbox *Sandbox) GetSSHCommand(ctx context.Context, extraArgs ...string) *exec.Cmd {
	args := []string{}
	args = append(args, "-F")
	args = append(args, sbox.SSHConfigFilePath)
	args = append(args, extraArgs...)
	return exec.CommandContext(ctx, "ssh", args...)
}

func (sbox *Sandbox) GetSCPCommand(ctx context.Context, extraArgs ...string) *exec.Cmd {
	args := []string{}
	args = append(args, "-F")
	args = append(args, sbox.SSHConfigFilePath)
	args = append(args, extraArgs...)
	return exec.CommandContext(ctx, "scp", args...)
}

func (sbox *Sandbox) Close() error {
	return os.RemoveAll(sbox.Dir)
}

func WaitForServerUp(ctx context.Context, address string, port uint16, waitFor time.Duration) bool {
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		dialer := net.Dialer{
			Timeout: 20 * time.Second,
		}
		c, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", address, port))
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

func FetchHostKeys(ctx context.Context, address string, port uint16) ([]HostKey, error) {
	out, err := exec.CommandContext(ctx, "ssh-keyscan", "-p", fmt.Sprintf("%d", port), address).Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return nil, errors.New(string(err.Stderr))
		}
		return nil, err
	}

	hostKeys, err := ParseHostKeys(out)
	if err != nil {
		return nil, err
	}

	return hostKeys, nil
}

// Generates a new unencrypted public/private keypair
func NewIdentity(ctx context.Context, keyType string, bits uint64) (Identity, error) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		return Identity{}, err
	}
	defer os.RemoveAll(d)

	privKeyPath := filepath.Join(d, "sshkey")
	pubKeyPath := privKeyPath + ".pub"

	_, err = exec.CommandContext(ctx, "ssh-keygen", "-C", "", "-b", fmt.Sprintf("%d", bits), "-t", keyType, "-N", "", "-f", privKeyPath).Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return Identity{}, errors.New(string(err.Stderr))
		}
		return Identity{}, err
	}

	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return Identity{}, err
	}

	pubKey, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		PrivateKey: string(privKey),
		PublicKey:  string(pubKey),
	}, nil
}
