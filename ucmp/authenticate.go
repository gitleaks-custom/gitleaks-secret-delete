package ucmp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	userAgentPrefix = "Gitleaks"
)

var callOnceAuthInstance sync.Once // Support Singleton
var validDomainList = []string{"lguplus.co.kr", "lgupluspartners.co.kr"}

type Auth struct {
	UserAgent      string
	BinaryCheckSum string
	Email          string
}

var authenticationInstance *Auth

func GetAuthenticationInstance() *Auth {
	if authenticationInstance == nil { // Singleton instance
		callOnceAuthInstance.Do(func() {
			authenticationInstance = &Auth{
				UserAgent:      userAgentPrefix,
				BinaryCheckSum: getChecksum(),
				Email:          getUserEmail(),
			}
		})
	}

	return authenticationInstance
}

func (auth *Auth) CheckValidEmail() bool {
	if auth.Email == "" {
		return false
	}

	parts := strings.Split(auth.Email, "@")
	if len(parts) != 2 {
		return false // 올바르지 않은 이메일 형식
	}
	domain := parts[1]

	for _, validDomain := range validDomainList {
		if domain == validDomain {
			return true
		}
	}

	return false
}

func (auth *Auth) GetValidDomainList() string {
	return strings.Join(validDomainList, ", ")
}

func getChecksum() string {
	exePath, err := os.Executable() // Current executable binary path
	if err != nil {
		return ""
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return ""
	}

	checksum := sha256.Sum256(data) // Get Checksum of the binary file

	return fmt.Sprintf("%x", checksum[:]) // Convert [32]byte to string
}
