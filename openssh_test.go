package openssh

import (
	"reflect"
	"testing"
)

func TestParsingKnownHosts(t *testing.T) {
	testFile := `

# test
35.192.13.61 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC1aC56LSAdkURFeZnUlenZXg9F1gT0pwGw9BYlaW36V comment
[127.0.0.1]:5555 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNDu83j9Vyo6Bvu+bnMd6ADnNU7r3jrQGoMl4UJWfQ78RpJ1uEvW8BYDi4i/jM6vyBGO1Jar1y3OlhHaGR+oE+Y=
gitlab.com,52.167.219.168 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBfVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
`

	expectedHostKeys := []HostKey{
		HostKey{
			Addresses: []HostKeyAddress{
				HostKeyAddress{
					Hostname: "35.192.13.61",
					Port:     22,
				},
			},
			KeyType: "ssh-ed25519",
			KeyData: "AAAAC3NzaC1lZDI1NTE5AAAAIC1aC56LSAdkURFeZnUlenZXg9F1gT0pwGw9BYlaW36V",
		},

		HostKey{
			Addresses: []HostKeyAddress{
				HostKeyAddress{
					Hostname: "127.0.0.1",
					Port:     5555,
				},
			},
			KeyType: "ecdsa-sha2-nistp256",
			KeyData: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNDu83j9Vyo6Bvu+bnMd6ADnNU7r3jrQGoMl4UJWfQ78RpJ1uEvW8BYDi4i/jM6vyBGO1Jar1y3OlhHaGR+oE+Y=",
		},

		HostKey{
			Addresses: []HostKeyAddress{
				HostKeyAddress{
					Hostname: "gitlab.com",
					Port:     22,
				},
				HostKeyAddress{
					Hostname: "52.167.219.168",
					Port:     22,
				},
			},
			KeyType: "ecdsa-sha2-nistp256",
			KeyData: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBfVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=",
		},
	}

	hostKeys, err := ParseHostKeys([]byte(testFile))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedHostKeys, hostKeys) {
		t.Fatalf("expected %#v != actual %#v", expectedHostKeys, hostKeys)
	}

}
