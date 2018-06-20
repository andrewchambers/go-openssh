package main

import (
	"context"
	"log"
	"os/exec"
	"time"

	"github.com/andrewchambers/go-openssh"
)

func main() {
	ctx := context.Background()

	if !openssh.WaitForServerUp(ctx, "acha.ninja", 22, 5*time.Second) {
		panic("ssh server not up")
	}

	hostKeys, err := openssh.FetchHostKeys(ctx, "acha.ninja", 22)
	if err != nil {
		panic(err)
	}

	log.Printf("%#v", hostKeys)

	identity, err := openssh.NewIdentity(ctx, "ed25519", 1028)
	if err != nil {
		panic(err)
	}

	log.Printf("%#v", identity)

	config := &openssh.Config{
		Identity:   identity,
		KnownHosts: openssh.KnownHosts{HostKeys: hostKeys},
	}

	sandbox, err := config.BuildSandbox()
	if err != nil {
		panic(err)
	}
	defer sandbox.Close()

	cmd := sandbox.GetSSHCommand(ctx, "-n", "ac@acha.ninja", "ls")
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
