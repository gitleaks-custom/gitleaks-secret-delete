package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/ucmp"
	"io"
	"net/http"
	"net/url"
)

func init() {
	auditCmd.Flags().String("url", "", "Backend URL")
	rootCmd.AddCommand(auditCmd)
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Send audit data to backend",
	Run:   runAudit,
}

type AuditRequest struct {
	OrganizationName string `json:"organizationName"`
	RepositoryName   string `json:"repositoryName"`
	BranchName       string `json:"branchName"`
	AuthorName       string `json:"authorName"`
	AuthorEmail      string `json:"authorEmail"`
	CommitHash       string `json:"commitHash"`
	CommitTimestamp  string `json:"commitTimestamp"`
}

type AuditResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}

const (
	responseStringGitConfig = "GitConfig"
	responseStringVersion   = "Version"
	responseStringMessage   = "Message"
)

func runAudit(cmd *cobra.Command, args []string) {
	// 로직상 오류가 발생해도 정상 리턴
	defer func() {
		recover()
		return
	}()

	log.Debug().Msg(fmt.Sprintf("UserAgent, %s", ucmp.Auth.UserAgent))
	log.Debug().Msg(fmt.Sprintf("checksum, %s", ucmp.Auth.BinaryCheckSum))
	log.Debug().Msg(fmt.Sprintf("email, %s", ucmp.Auth.Email))

	// 디버깅 옵션 활성시 로그 표시
	debugging := ucmp.GetGitleaksConfigBoolean(ucmp.ConfigDebug)
	if debugging {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Check .git/config - Gitleaks.Enable
	isEnable := ucmp.GetGitleaksConfigBoolean(ucmp.ConfigEnable)
	if !isEnable {
		if debugging {
			log.Error().Msg("Gitleaks is not enabled")
		}
		return
	}

	// Check .git/config - Gitleaks.Scanned
	isScanned := ucmp.GetGitleaksConfigBoolean(ucmp.ConfigScanned)
	if !isScanned {
		if debugging {
			log.Error().Msg("Staged files are not scanned")
		}
		// Pre-commmit (gitleaks protect) 단계에서 종료시
		// 1. Secret 발견
		// 2. Pre-commit (gitleaks protect) 미 수행
		return
	}

	_, err := ucmp.DeleteGitleaksConfig(ucmp.ConfigScanned)
	if err != nil {
		// don't exit on error
		log.Error().Err(err).Msg("")
	}

	// Check Email is lguplus.co.kr or lgupluspartners.co.kr
	if !ucmp.Auth.CheckValidEmail() {
		log.Error().Msg("Email is not lguplus.co.kr or lgupluspartners.co.kr")
		return
	}

	backendUrl, _ := ucmp.GetGitleaksConfig(ucmp.ConfigUrl)

	log.Debug().Str("Url", backendUrl).Msg("Request")

	u, err := url.Parse(backendUrl)
	// net/url Parsing Error
	if err != nil {
		if debugging {
			log.Error().Msg("Error Parsing URL ," + err.Error())
		}
		panic(err)
	}

	// Request Handling
	requestData, _ := json.Marshal(retrieveLocalGitInfo())

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBuffer(requestData))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", ucmp.Auth.UserAgent+"/"+Version)
	req.SetBasicAuth(Version, ucmp.Auth.BinaryCheckSum)

	log.Debug().RawJSON("Body", requestData).Msg("Request")

	client := &http.Client{}
	resp, err := client.Do(req)
	// net/http client Error - Request 오류 시 백엔드 통신 X
	if err != nil {
		if debugging {
			log.Error().Msg("Http Request Error, " + err.Error())
		}
		panic(err)
	}
	defer resp.Body.Close()

	// Response Handling
	response, _ := io.ReadAll(resp.Body)

	// Response Handling
	var responseData AuditResponse
	log.Debug().RawJSON("Body", response).Msg("Response")
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		if debugging {
			log.Error().Msg("Json Unmarshal Error, " + err.Error())
		}
		panic(err)
	}

	data, ok := responseData.Data.(map[string]interface{})
	if !ok {
		// Data 필드가 map[string]interface{} 타입이 아님.
		// 서버 Response 오류
		log.Fatal().Err(err).Msg("")
	}

	// GitConfig 필드 처리
	// TODO: enable false 로 응답 받은 경우 post-commit 삭제 필요.
	if gitConfig, isGitConfigRespond := data[responseStringGitConfig].(map[string]interface{}); isGitConfigRespond {
		log.Debug().Interface("Body.Data."+responseStringGitConfig, gitConfig).Msg("Response")
		for k, v := range gitConfig {
			ucmp.SetGitleaksConfig(k, fmt.Sprintf("%v", v))
		}
	}

	// Version, Message 필드 처리
	version, isVersionRespond := data[responseStringVersion]
	message, isMessageRespond := data[responseStringMessage]

	if isVersionRespond && (version != Version) {
		log.Debug().Interface("Body.Data."+responseStringVersion, version).Msg("Response")
		if isMessageRespond {
			log.Debug().Interface("Body.Data."+responseStringMessage, message).Msg("Response")
			log.Info().Msgf("%s", message)
		}
	}
}

func retrieveLocalGitInfo() AuditRequest {
	OrganizationName, _ := ucmp.GetLocalOrganizationName()
	RepositoryName, _ := ucmp.GetLocalRepositoryName()
	BranchName, _ := ucmp.GetHeadBranchName()
	AuthorName, _ := ucmp.GetUserName()
	AuthorEmail, _ := ucmp.GetUserEmail()
	CommitHash, _ := ucmp.GetHeadCommitHash()
	CommitTimestamp, _ := ucmp.GetHeadCommitTimestamp()

	return AuditRequest{
		OrganizationName,
		RepositoryName,
		BranchName,
		AuthorName,
		AuthorEmail,
		CommitHash,
		CommitTimestamp,
	}
}
