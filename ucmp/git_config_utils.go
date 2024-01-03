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

type GitScope int

const (
	GIT_SCOPE_LOCAL  GitScope = iota
	GIT_SCOPE_GLOBAL GitScope = iota
	GIT_SCOPE_SYSTEM GitScope = iota
	GIT_SCOPE_ENTIRE GitScope = iota
)

const (
	audit_config_prefix = "Gitleaks."
)

func getGitConfig(scope GitScope, key string) (string, error) {
	switch scope {
	case GIT_SCOPE_LOCAL:
		return execGitCommand("config", "--get", "--null", "--local", key)
	case GIT_SCOPE_GLOBAL:
		return execGitCommand("config", "--get", "--null", "--global", key)
	case GIT_SCOPE_SYSTEM:
		return execGitCommand("config", "--get", "--null", "--system", key)
	default:
		return execGitCommand("config", "--get", "--null", key)
	}
}

func getAuditConfigString(scope GitScope, key AUDIT_CONFIG) (string, error) {

	searchKey := audit_config_prefix + key

	value, err := getGitConfig(scope, string(searchKey))
	if err != nil {
		return "", err
	}
	return value, nil
}

func getAuditConfigBoolean(scope GitScope, key AUDIT_CONFIG) (bool, error) {

	searchKey := audit_config_prefix + key

	value, err := getGitConfig(scope, string(searchKey))
	if err != nil {
		return false, err
	}

	flag, err := strconv.ParseBool(value)
	if err != nil {
		return false, err
	}

	return flag, nil
}

func getAuditConfigInt64(scope GitScope, key AUDIT_CONFIG) (int64, error) {

	searchKey := audit_config_prefix + key

	value, err := getGitConfig(scope, string(searchKey))
	if err != nil {
		return 0, err
	}

	intValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}

	return intValue, nil
}

func setAuditConfig(scope GitScope, key string, value string) (string, error) {

	searchKey := audit_config_prefix + key

	switch scope {
	case GIT_SCOPE_LOCAL:
		return execGitCommand("config", "--local", searchKey, value)
	case GIT_SCOPE_GLOBAL:
		return execGitCommand("config", "--global", searchKey, value)
	case GIT_SCOPE_SYSTEM:
		return execGitCommand("config", "--system", searchKey, value)
	default:
		return execGitCommand("config", "--local", searchKey, value)
	}
}

func deleteAuditConfig(scope GitScope, key string) (string, error) {

	searchKey := audit_config_prefix + key

	switch scope {
	case GIT_SCOPE_LOCAL:
		return execGitCommand("config", "--local", "--unset", searchKey)
	case GIT_SCOPE_GLOBAL:
		return execGitCommand("config", "--global", "--unset", searchKey)
	case GIT_SCOPE_SYSTEM:
		return execGitCommand("config", "--system", "--unset", searchKey)
	default:
		return execGitCommand("config", "--local", "--unset", searchKey)
	}
}

func getUserName() string {
	userName, err := getGitConfig(GIT_SCOPE_ENTIRE, "user.name")
	if err != nil {
		return ""
	}
	return userName
}

func getUserEmail() string {
	userEmail, err := getGitConfig(GIT_SCOPE_ENTIRE, "user.email")
	if err != nil {
		return ""
	}
	return userEmail
}

func getHeadCommitHash() string {
	commitHash, err := execGitCommand("rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return commitHash
}

func getHeadCommitTimestamp() string {
	commitTimestamp, err := execGitCommand("show", "-s", "--format=%ct")
	if err != nil {
		return ""
	}
	return commitTimestamp
}

func getHeadBranchName() string {
	branchName, err := execGitCommand("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return ""
	}
	return branchName
}

func getLocalRemoteOriginUrl() (string, error) {
	return getGitConfig(GIT_SCOPE_LOCAL, "remote.origin.url")
}

func getLocalRepositoryName() string {
	url, err := getLocalRemoteOriginUrl()
	if err != nil {
		return ""
	}

	repo := retrieveRepoName(url)
	return repo
}

func getLocalOrganizationName() string {
	url, err := getLocalRemoteOriginUrl()
	if err != nil {
		return ""
	}

	orga := retrieveOrgaName(url)
	return orga
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

type ErrNotFound struct {
	Key string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("the key `%s` is not found", e.Key)
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
