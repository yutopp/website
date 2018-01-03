package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const UpdaterPath = "hugo"

func main() {
	baseDir := flag.String("base-dir", "/workdir", "Base directory for git clone/pull")
	key := flag.String("key", "", "Key for signature of github webhook")
	bind := flag.String("bind", "0.0.0.0:8080", "Bind address")
	flag.Parse()

	log.Printf("Started: %s", *bind)

	http.HandleFunc("/", updateWebsite(*baseDir, *key))
	if err := http.ListenAndServe(*bind, nil); err != nil {
		log.Fatal(err)
	}
}

type request struct {
	Repository struct {
		Name     string `json:"name"`
		CloneUrl string `json:"clone_url"`
	} `json:"repository"`
}

func updateWebsite(baseDir, key string) func(http.ResponseWriter, *http.Request) {
	const SignatureLen = 45 // "sha1=" + hash

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if r.Method != http.MethodPost {
			http.Error(w, "Method must be POST", http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}

		signature := []byte(r.Header.Get("X-Hub-Signature"))
		if l := len(signature); l != SignatureLen {
			http.Error(w, "signature has unexpected length", http.StatusBadRequest)
			return
		}

		mac := hmac.New(sha1.New, []byte(key))
		mac.Write(body)
		signatureActual := []byte(mac.Sum(nil))

		signatureExpected := make([]byte, hex.DecodedLen(len(signature[5:])))
		n, err := hex.Decode(signatureExpected, signature[5:])
		if err != nil {
			http.Error(w, "failed to decode signature", http.StatusBadRequest)
			return
		}

		log.Printf("signatureExpected = %x", signatureExpected)
		log.Printf("signatureActual = %x", signatureActual)

		if !hmac.Equal(signatureExpected[:n], signatureActual) {
			http.Error(w, "signature is not matched", http.StatusBadRequest)
			return
		}

		var hookRequest request
		if err := json.Unmarshal(body, &hookRequest); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := prepareRepo(
			baseDir,
			hookRequest.Repository.Name,
			hookRequest.Repository.CloneUrl,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := updateSite(
			baseDir,
			hookRequest.Repository.Name,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
	}
}

type chdir struct {
	prevPath string
}

func Chdir(path string) (*chdir, error) {
	prev, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(path); err != nil {
		return nil, err
	}
	return &chdir{
		prevPath: prev,
	}, nil
}

func (c *chdir) reset() {
	if err := os.Chdir(c.prevPath); err != nil {
		panic(err)
	}
}

func prepareRepo(baseDir, name, repoUrl string) error {
	var commands []string

	repoDir := filepath.Join(baseDir, name)
	if _, err := os.Stat(repoDir); err != nil {
		// not exists, clone repo
		c, err := Chdir(baseDir)
		if err != nil {
			return err
		}
		defer c.reset()

		commands = []string{"git", "clone", repoUrl, "--depth", "1"}
	} else {
		// already exists, pull repository
		c, err := Chdir(repoDir)
		if err != nil {
			return err
		}
		defer c.reset()

		commands = []string{"git", "reset", "--hard", "origin/master"}
	}

	return executeCommand(commands)
}

func updateSite(baseDir, name string) error {
	repoDir := filepath.Join(baseDir, name)
	c, err := Chdir(repoDir)
	if err != nil {
		return err
	}
	defer c.reset()

	return executeCommand([]string{UpdaterPath})
}

func executeCommand(commands []string) error {
	if len(commands) < 1 {
		return fmt.Errorf("number of commands is not enought")
	}

	log.Printf("execute: %c", commands)
	cmd := exec.Command(commands[0], commands[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	log.Printf("succeeded")

	return nil
}
