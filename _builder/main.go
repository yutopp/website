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
	"regexp"
)

const UpdaterPath = "hugo"

type config struct {
	baseDir   string
	key       string
	refRegexp *regexp.Regexp
}

func main() {
	baseDir := flag.String("base-dir", "/workdir", "Base directory for git clone/pull")
	key := flag.String("key", "", "Key for signature of github webhook")
	bind := flag.String("bind", "0.0.0.0:8080", "Bind address")
	ref := flag.String("ref", "refs/heads/master", "Regexp for branch filterling")
	flag.Parse()

	refRegexp, err := regexp.Compile(*ref)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Started: %s", *bind)

	http.HandleFunc("/", updateWebsite(&config{
		baseDir:   *baseDir,
		key:       *key,
		refRegexp: refRegexp,
	}))
	if err := http.ListenAndServe(*bind, nil); err != nil {
		log.Fatal(err)
	}
}

type request struct {
	Ref        string `json:"ref"`
	HeadCommit struct {
		Id string `json:"id"`
	} `json:"head_commit"`
	Repository struct {
		Name     string `json:"name"`
		CloneUrl string `json:"clone_url"`
	} `json:"repository"`
}

func updateWebsite(c *config) func(http.ResponseWriter, *http.Request) {
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

		mac := hmac.New(sha1.New, []byte(c.key))
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

		event := r.Header.Get("X-GitHub-Event")
		switch event {
		case "ping":
			w.Write([]byte("OK PING"))

		case "push":
			var hookRequest request
			if err := json.Unmarshal(body, &hookRequest); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			log.Printf("hash: %s", hookRequest.HeadCommit.Id)

			if !c.refRegexp.MatchString(hookRequest.Ref) {
				w.Write([]byte("OK PUSH (IGNORED: ref not matched)"))
				return
			}

			if err := prepareRepo(
				c.baseDir,
				hookRequest.Repository.Name,
				hookRequest.Repository.CloneUrl,
				hookRequest.HeadCommit.Id,
			); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if err := updateSite(
				c.baseDir,
				hookRequest.Repository.Name,
			); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Write([]byte("OK PUSH"))

		default:
			http.Error(w, fmt.Sprintf("unsupported event: %s", event), http.StatusBadRequest)
		}
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

type command struct {
	path string
	args []string
}

func prepareRepo(baseDir, name, repoUrl, commitHash string) error {
	var commands []*command

	repoDir := filepath.Join(baseDir, name)
	if _, err := os.Stat(repoDir); err != nil {
		// not exists, clone repo
		c, err := Chdir(baseDir)
		if err != nil {
			return err
		}
		defer c.reset()

		commands = []*command{
			&command{"git", []string{"clone", repoUrl, "--depth", "1"}},
		}
	} else {
		// already exists, pull repository
		c, err := Chdir(repoDir)
		if err != nil {
			return err
		}
		defer c.reset()

		commands = []*command{
			&command{"git", []string{"fetch"}},
			&command{"git", []string{"reset", "--hard", commitHash}},
		}
	}

	return executeCommands(commands)
}

func updateSite(baseDir, name string) error {
	repoDir := filepath.Join(baseDir, name)
	c, err := Chdir(repoDir)
	if err != nil {
		return err
	}
	defer c.reset()

	return executeCommand(&command{UpdaterPath, []string{}})
}

func executeCommands(commands []*command) error {
	for _, command := range commands {
		if err := executeCommand(command); err != nil {
			return err
		}
	}

	return nil
}

func executeCommand(command *command) error {
	log.Printf("execute: %v", command)
	cmd := exec.Command(command.path, command.args...)
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
