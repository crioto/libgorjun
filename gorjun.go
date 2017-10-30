package gorjun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

// GorjunServer is a representation for Gorjun bucket
type GorjunServer struct {
	Username     string // Username of gorjun user
	Email        string // Email used to identify user in GPG
	Hostname     string // Hostname of the Gorjun server
	GPGDirectory string // GPGDirectory points to a gnupg directory in the file system
	Token        string // Active token
	TokenCode    string // Clean token code
	Passphrase   string // Passphrase used to decrypt private key
}

// GorjunFileHash contents different types of file hashed
type GorjunFileHash struct {
	MD5 string `json:"md5"`
	SHA string `json:"sha"`
}

// GorjunFile is a file located on Gorjun bucket server
type GorjunFile struct {
	Id    string         `json:"id"`
	Size  int            `json:"size"`
	Name  string         `json:"name"`
	Owner []string       `json:"owner"`
	Hash  GorjunFileHash `json:"hash"`
}

// ListUserFiles returns a list of files that belongs to user
func (g *GorjunServer) ListUserFiles() ([]GorjunFile, error) {
	resp, err := http.Get(fmt.Sprintf("https://%s/kurjun/rest/raw/info?owner=%s", g.Hostname, g.Username))
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve file list from %s: %v", g.Hostname, err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to read body from %s: %v", g.Hostname, err)
	}
	var rf []GorjunFile
	err = json.Unmarshal(data, &rf)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal contents from %s: %v", g.Hostname, err)
	}
	return rf, nil
}

// GetFileByName will return information about a file with specified name
func (g *GorjunServer) GetFileByName(filename string) ([]GorjunFile, error) {
	resp, err := http.Get(fmt.Sprintf("https://%s/kurjun/rest/raw/info?name=%s", g.Hostname, filename))
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve file information from %s: %v", g.Hostname, err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to read body from %s: %v", g.Hostname, err)
	}
	var f []GorjunFile
	err = json.Unmarshal(data, &f)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal contents from %s: %v", g.Hostname, err)
	}
	return f, nil
}

// UploadFile will upload file and return it's ID after successful upload
func (g *GorjunServer) UploadFile(filename string) (string, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return "", fmt.Errorf("%s not found", filename)
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("Failed to open file: %v", err)
	}
	defer f.Close()
	fw, err := w.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return "", fmt.Errorf("Failed to create file form: %v", err)
	}
	if _, err = io.Copy(fw, f); err != nil {
		return "", fmt.Errorf("Failed to copy file contents: %v", err)
	}
	if fw, err = w.CreateFormField("token"); err != nil {
		return "", fmt.Errorf("Failed to create token form field: %v", err)
	}
	if _, err = fw.Write([]byte(g.Token)); err != nil {
		return "", fmt.Errorf("Failed to write token: %v", err)
	}w.Close()

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/kurjun/rest/raw/upload", g.Hostname), &b)
	if err != nil {
		return "", fmt.Errorf("Failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to execute HTTP request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Upload failed. Server returned %s error", res.Status)
	}
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read response body: %v", err)
	}
	return string(response), nil
}

// RemoveFile will delete file on gorjun with specified name. If multiple files with the same
// name exists belong to the same user only the last one (most recent) will be removed
func (g *GorjunServer) RemoveFile(filename string) error {
	file, err := g.GetFileByName(filename)
	if err != nil {
		return fmt.Errorf("Failed to get file: %v", err)
	}
	return g.RemoveFileByID(file[0].Id)
}

// RemoveFileByID will remove file with specified ID
func (g *GorjunServer) RemoveFileByID(ID string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://%s/kurjun/rest/raw/delete?id=%s&token=%s", g.Hostname, ID, g.Token), nil)
	if err != nil {
		return fmt.Errorf("Failed to remove file [%s]: %s", ID, err)
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to remove file: %s", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Can't remove file - HTTP request returned %s code", res.Status)
	}
	return nil
}

// DownloadFile will download file with specified name into the specified output directory
func (g *GorjunServer) DownloadFile(filename, outputDirectory string) error {
	return nil
}

// DownloadFileByID will download file with specified ID into the specified output directory
func (g *GorjunServer) DownloadFileByID(ID, outputDirectory string) error {
	return nil
}
