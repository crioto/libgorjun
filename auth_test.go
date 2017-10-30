package gorjun

import (
	"fmt"
	"os"
	"testing"
)

func TestGetAuthTokenCode(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	g.Username = "user"
	err := g.GetAuthTokenCode()
	if err != nil {
		t.Errorf("Failed to retrieve token: %v", err)
	}
	if len(g.TokenCode) != 32 {
		t.Errorf("Token length doesn't equals 32 symbols: %d", len(g.TokenCode))
	}
}

func TestSignToken(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	g.Username = "user"
	g.Email = "email@example.com"
	g.GPGDirectory = os.Getenv("HOME") + "/.gnupg"
	str, err := g.SignToken("111")
	if err != nil {
		t.Errorf("Failed to sign token: %v", err)
	}
	fmt.Printf("Str: %s", str)
}

func TestDecodePrivateKey(t *testing.T) {
	g := new(GorjunServer)
	g.GPGDirectory = os.Getenv("HOME") + "/.gnupg"
	key, err := g.decodePrivateKey()
	if err != nil {
		t.Errorf("%s", err)
	}
	if key == nil {
		t.Errorf("Failed to decode private key")
	}
}

func TestGetActiveToken(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	g.Username = "user"
	g.Email = "email@example.com"
	g.GPGDirectory = os.Getenv("HOME") + "/.gnupg"
	g.Passphrase = ""
	err := g.GetAuthTokenCode()
	if err != nil {
		t.Errorf("Failed to retrieve token: %v", err)
	}
	fmt.Printf("Token code: %s\n", g.TokenCode)
	sign, err := g.SignToken(g.TokenCode)
	if err != nil {
		t.Errorf("Failed to sign token code: %v", err)
	}
	fmt.Printf("Signed token code: %s\n", sign)
	err = g.GetActiveToken(sign)
	if err != nil {
		t.Errorf("Failed to get active token: %v", err)
	}
	fmt.Printf("Active token: %s, len: %d\n", g.Token, len(g.Token))
}
