package ucmp

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
)

const (
	// CoreHooksPath is In User Home Directory
	CoreHooksPath               = ".githooks"
	PreCommitScriptPath         = CoreHooksPath + "/pre-commit"
	PostCommitScriptPath        = CoreHooksPath + "/post-commit"
	PreCommitScript             = "gitleaks protect --no-banner --verbose --staged"
	PostCommitScript            = "gitleaks audit"
	LocalPreCommitSupportScript = `
LOCAL_PRE_COMMIT_HOOK=".git/hooks/pre-commit"

if [ -x "$LOCAL_PRE_COMMIT_HOOK" ]; then
    "$LOCAL_PRE_COMMIT_HOOK"
    RESULT=$?

    if [ $RESULT -ne 0 ]; then
        exit 1
    fi
fi
`
)

func ensureHooksPath() {
	homeDir, _ := os.UserHomeDir()
	filepath := path.Join(homeDir, CoreHooksPath)

	_, err := os.Stat(filepath)
	if err != nil {
		_ = os.Mkdir(filepath, 0755)
	}
}

func getFileContents(filepath string) (string, error) {
	content, err := os.ReadFile(filepath)

	if err != nil {
		// fmt.Printf("Error Reading File Contents: %v\n", err)
		return "", err
	}

	return string(content), nil
}

func InstallGitHookScript(filepath string, script string) {
	ensureHooksPath()

	// Override the filepath to be under the user's home directory
	homeDir, _ := os.UserHomeDir()
	filepath = path.Join(homeDir, filepath)
	content, _ := getFileContents(filepath)
	content = strings.TrimRight(content, "\r\n")

	var newContent strings.Builder
	if len(content) > 0 {
		newContent.WriteString(content)
		// 이미 스크립트가 있다면 추가하지 않음
		if strings.Contains(content, script) {
			return
		}
		newContent.WriteString("\n") // 기존 내용과 새 내용 사이에 줄바꿈 추가
	}

	// shebang 추가
	if !strings.Contains(content, "#!/") {
		switch runtime.GOOS {
		case "windows":
			newContent.WriteString("#!/bin/sh\n")
		default:
			newContent.WriteString("#!/usr/bin/env bash\n")
		}
	}

	newContent.WriteString(script) // 새 스크립트 추가

	err := os.WriteFile(filepath, []byte(newContent.String()), 0755)
	if err != nil {
		fmt.Printf("Error Writing Git Hook Script: %v\n", err)
		return
	}
}

func UninstallGitHookScript(filepath string, script string) {
	ensureHooksPath()

	// Override the filepath to be under the user's home directory
	homeDir, _ := os.UserHomeDir()
	filepath = path.Join(homeDir, filepath)

	content, _ := getFileContents(filepath)
	if len(content) == 0 {
		return
	}

	// 주어진 스크립트 내용을 제거
	newContent := strings.ReplaceAll(content, script, "")

	err := os.WriteFile(filepath, []byte(newContent), 0755)
	if err != nil {
		fmt.Printf("Error Removing Git Hook Script: %v\n", err)
		return
	}
}
