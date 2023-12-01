package ucmp

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	ConfigDebug   = "debug"
	ConfigEnable  = "enable"
	ConfigScanned = "scanned"
	ConfigUrl     = "url"
)

type ErrNotFound struct {
	Key string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("the key `%s` is not found", e.Key)
}

func SetGitleaksConfig(key string, value string) (string, error) {
	return execGitCommand("config", "--local", "Gitleaks."+key, value)
}

func GetGitleaksConfig(key string) (string, error) {
	searchString := "Gitleaks." + key
	return local(searchString)
}

func DeleteGitleaksConfig(key string) (string, error) {
	searchString := "Gitleaks." + key
	return execGitCommand("config", "--local", "--unset", searchString)
}

// Return true Only if [Gitleaks.Key = true] in .git/config
func GetGitleaksConfigBoolean(key string) bool {
	value, err := GetGitleaksConfig(key)
	if err != nil {
		return false
	}

	flag, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}

	return flag
}

// Git Config 에서 Key 를 탐색
func entire(key string) (string, error) {
	return execGitCommand("config", "--get", "--null", key)
}

// Global Git Config 에서 Key 를 탐색
func global(key string) (string, error) {
	return execGitCommand("config", "--get", "--null", "--global", key)
}

// Local Git Config 에서 Key 를 탐색
func local(key string) (string, error) {
	return execGitCommand("config", "--get", "--null", "--local", key)
}

func GetUserName() (string, error) {
	return entire("user.name")
}

func GetUserEmail() (string, error) {
	return entire("user.email")
}

func GetHeadCommitHash() (string, error) {
	return execGitCommand("rev-parse", "HEAD")
}

func GetHeadCommitTimestamp() (string, error) {
	return execGitCommand("show", "-s", "--format=%ct")
}

func GetHeadBranchName() (string, error) {
	return execGitCommand("rev-parse", "--abbrev-ref", "HEAD")
}

func getLocalRemoteOriginUrl() (string, error) {
	return local("remote.origin.url")
}

func GetLocalRepositoryName() (string, error) {
	url, err := getLocalRemoteOriginUrl()
	if err != nil {
		return "", err
	}

	repo := retrieveRepoName(url)
	return repo, nil
}

func GetLocalOrganizationName() (string, error) {
	url, err := getLocalRemoteOriginUrl()
	if err != nil {
		return "", err
	}

	orga := retrieveOrgaName(url)
	return orga, nil
}

var repoNameRegexp = regexp.MustCompile(`.+/([^/]+)(\.git)?$`)
var orgNameRegexp = regexp.MustCompile(`[:/]([^/]+)/[^/]+(\.git)?$`)

func retrieveRepoName(url string) string {
	matched := repoNameRegexp.FindStringSubmatch(url)
	return strings.TrimSuffix(matched[1], ".git")
}

func retrieveOrgaName(url string) string {
	matched := orgNameRegexp.FindStringSubmatch(url)
	if len(matched) >= 2 {
		orgName := matched[1] // The organization name is captured in the first submatch.
		return orgName
	}
	return ""
}

func execGitCommand(args ...string) (string, error) {
	// gitArgs := append([]string{"config", "--get", "--null"}, args...)
	gitArgs := args
	var stdout bytes.Buffer
	cmd := exec.Command("git", gitArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard

	err := cmd.Run()
	if exitError, ok := err.(*exec.ExitError); ok {
		if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if waitStatus.ExitStatus() == 1 {
				return "", &ErrNotFound{Key: args[len(args)-1]}
			}
		}
		return "", err
	}

	cmdResult := stdout.String()
	cmdResult = strings.TrimRight(cmdResult, "\n")
	cmdResult = strings.TrimRight(cmdResult, "\000")

	return cmdResult, nil
}
