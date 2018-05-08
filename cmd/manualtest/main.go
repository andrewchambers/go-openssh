package main

import (
	"time"
	"log"
	"os/exec"

	"github.com/andrewchambers/openssh"
)


func main () {
	if ! openssh.WaitForServerUp("acha.ninja", 22, 5 * time.Second) {
		panic("ssh server not up")
	}

	knownHosts, err := openssh.FetchHostKeys("acha.ninja", 22)
	if err != nil {
		panic(err)
	}

	log.Printf("%#v", knownHosts)

	identity, err := openssh.NewIdentity("ed25519", 1028)
	if err != nil {
		panic(err)
	}

	log.Printf("%#v", identity)

	config := &openssh.SSHConfig{
		Identity: identity,
		KnownHosts: knownHosts,
	}

	sandbox, err := config.BuildSandbox()
	if err != nil {
		panic(err)
	}
	//defer sandbox.Close()
	log.Printf("sandbox.Dir = %s", sandbox.Dir)

	cmd := sandbox.GetSSHCommand("-n", "ac@acha.ninja", "ls")
	cmd.Stdin = nil

	log.Printf("%#v", cmd)

	out, err := cmd.Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			panic(string(err.Stderr))
		}
		panic(err)
	}

	log.Printf("%#v", out)

}