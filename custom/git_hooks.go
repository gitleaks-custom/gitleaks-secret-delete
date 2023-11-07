package lib

import (
	"fmt"
	"os"
	"strings"
)

const (
	PreCommitScriptPath  = ".git/hooks/pre-commit"
	PostCommitScriptPath = ".git/hooks/post-commit"
	PreCommitScript      = "gitleaks protect --no-banner --verbose --staged"
	PostCommitScript     = "gitleaks audit"
)

func getFileContents(filepath string) (string, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		// fmt.Printf("Error Reading File Contents: %v\n", err)
		return "", err
	}

	return string(content), nil
}

func EnableGitHooks(filepath string, script string) {
	var newContent strings.Builder

	content, _ := getFileContents(filepath)

	if len(content) > 0 {
		newContent.WriteString(content)
	}

	if !strings.Contains(content, "#!/") {
		newContent.WriteString("#!/bin/sh\n")
	}

	if !strings.Contains(content, script) {
		newContent.WriteString(script)
	}

	err := os.WriteFile(filepath, []byte(newContent.String()), 0755)
	if err != nil {
		fmt.Printf("Error Appending PreCommit Script: %v\n", err)
		return
	}
}

func DisableGitHooks(filepath string, script string) {
	content, _ := getFileContents(filepath)
	if len(content) == 0 {
		return
	}
	var newContent string
	newContent = content

	if strings.Contains(content, script) {
		newContent = strings.Replace(string(content), script, "", -1)
	}

	err := os.WriteFile(filepath, []byte(newContent), 0755)
	if err != nil {
		fmt.Printf("Error Appending PreCommit Script: %v\n", err)
		return
	}
}
