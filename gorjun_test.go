package gorjun

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestListUserFiles(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	g.Username = "user"
	flist, err := g.ListUserFiles()
	if err != nil {
		t.Errorf("Failed to retrieve user files: %v", err)
	}
	if len(flist) <= 0 {
		t.Errorf("Resulting array is empty")
	}
}

func TestUploadFile(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	err := g.AuthenticateUser("user", "email@example.com", "gpgpassphrase", "")
	if err != nil {
		t.Errorf("Authnetication failure: %v", err)
	}
	d1 := []byte("This is a test file\n")
	ioutil.WriteFile("/tmp/libgorjun-test", d1, 0644)
	id, err := g.UploadFile("/tmp/libgorjun-test")
	if err != nil {
		t.Errorf("Failed to upload: %v", err)
	}
	fmt.Printf("File ID: %s", id)
}

func TestGetFileByName(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	file, err := g.GetFileByName("libgorjun-test")
	if err != nil {
		t.Errorf("Failed to get file by name: %s", err)
	}
	fmt.Printf("File: %+v\n", file)
}

func TestRemoveFile(t *testing.T) {
	g := new(GorjunServer)
	g.Hostname = "cdn.subut.ai:8338"
	err := g.AuthenticateUser("user", "email@example.com", "gpgpassphrase", "")
	if err != nil {
		t.Errorf("Authnetication failure: %v", err)
	}
	err = g.RemoveFile("libgorjun-test")
	if err != nil {
		t.Errorf("Failed to remove file: %v", err)
	}
}
