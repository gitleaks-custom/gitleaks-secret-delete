package ucmp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

const (
	userAgentPrefix = "Gitleaks"
)

func init() {
	Auth.Init()
}

// Module Instance
var Auth auth

type auth struct {
	UserAgent      string
	BinaryCheckSum string
	Email          string
}

func (auth *auth) Init() {
	auth.UserAgent = userAgentPrefix
	auth.BinaryCheckSum, _ = getChecksum()
	auth.Email, _ = GetUserEmail()
}

func (auth *auth) CheckValidEmail() bool {
	if auth.Email == "" {
		return false
	}

	// 이메일 주소에서 도메인 부분 추출
	parts := strings.Split(auth.Email, "@")
	if len(parts) != 2 {
		return false // 올바르지 않은 이메일 형식
	}
	domain := parts[1]

	// 도메인이 lguplus.co.kr 또는 lgupluspartners.co.kr 인지 확인
	return domain == "lguplus.co.kr" || domain == "lgupluspartners.co.kr"
}

func getChecksum() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return "", err
	}

	checksum := sha256.Sum256(data)

	return fmt.Sprintf("%x", checksum[:]), nil
}
