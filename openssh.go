package openssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

func ParseKnownHosts(input []byte) (KnownHosts, error) {
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
				return KnownHosts{}, malformedErr()
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
							return KnownHosts{}, malformedErr()
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
							return KnownHosts{}, malformedErr()
						}
						st = 3
					case 3:
						_, _ = portBuf.WriteRune(c)
					}
				}

				if st != 3 {
					return KnownHosts{}, malformedErr()
				}

				p, err := strconv.ParseUint(portBuf.String(), 10, 16)
				if err != nil {
					return KnownHosts{}, malformedErr()
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
			return KnownHosts{}, err
		}
	}

	return KnownHosts{
		HostKeys: hostKeys,
	}, nil
}

type SSHConfig struct {
	Identity   Identity
	KnownHosts KnownHosts
}

type Identity struct {
	PublicKey  string
	PrivateKey string
}

func (config *SSHConfig) BuildSandbox() (*Sandbox, error) {
	dir, err := ioutil.TempDir("", "")
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

		knownHostsFilePath: knownHostsFilePath,
		privateKeyFilePath: privateKeyFilePath,
		sshConfigFilePath:  sshConfigFilePath,
	}, nil
}

// A sandbox is an ssh known hosts file, ssh key and a private key
// in a temporary directory, it allows you to execute openssh commands.
type Sandbox struct {
	Dir string

	knownHostsFilePath string
	privateKeyFilePath string
	sshConfigFilePath  string
}

func (sbox *Sandbox) GetSSHCommand(extraArgs ...string) *exec.Cmd {
	args := []string{}
	args = append(args, "-F")
	args = append(args, sbox.sshConfigFilePath)
	args = append(args, extraArgs...)
	return exec.Command("ssh", args...)
}

func (sbox *Sandbox) GetSCPCommand(extraArgs ...string) *exec.Cmd {
	args := []string{}
	args = append(args, "-F")
	args = append(args, sbox.sshConfigFilePath)
	args = append(args, extraArgs...)
	return exec.Command("scp", args...)
}

func (sbox *Sandbox) Close() error {
	return os.RemoveAll(sbox.Dir)
}

func WaitForServerUp(address string, port uint16, waitFor time.Duration) bool {
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

func FetchHostKeys(address string, port uint) (KnownHosts, error) {
	out, err := exec.Command("ssh-keyscan", "-p", fmt.Sprintf("%d", port), address).Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return KnownHosts{}, errors.New(string(err.Stderr))
		}
		return KnownHosts{}, err
	}

	knownHosts, err := ParseKnownHosts(out)
	if err != nil {
		return KnownHosts{}, err
	}

	return knownHosts, nil
}

// Generates a new unencrypted public/private keypair
func NewIdentity(keyType string, bits uint64) (Identity, error) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		return Identity{}, err
	}
	defer os.RemoveAll(d)

	privKeyPath := filepath.Join(d, "sshkey")
	pubKeyPath := privKeyPath + ".pub"

	_, err = exec.Command("ssh-keygen", "-C", "", "-b", fmt.Sprintf("%d", bits), "-t", keyType, "-N", "", "-f", privKeyPath).Output()
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
