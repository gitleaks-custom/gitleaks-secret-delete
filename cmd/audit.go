package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	Custom "github.com/zricethezav/gitleaks/v8/custom"
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

	// 디버깅 옵션 활성시 로그 표시
	debugging := Custom.GetGitleaksConfigBoolean(Custom.ConfigDebug)
	if debugging {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Pre-Commit protect 단계에서 스캔 정상 완료 체크
	isScanned := Custom.GetGitleaksConfigBoolean(Custom.ConfigScanned)
	if !isScanned {
		if debugging {
			log.Error().Msg("Staged files are not scanned")
		}
		// protect 과정에서 비정상 종료 (secret 발견) 시 audit return
		return
	}

	_, err := Custom.DeleteGitleaksConfig(Custom.ConfigScanned)
	if err != nil {
		// don't exit on error
		log.Error().Err(err).Msg("")
	}

	isEnable := Custom.GetGitleaksConfigBoolean(Custom.ConfigEnable)
	// isDebug := Custom.GetGitleaksConfigBoolean("debug")
	if !isEnable {
		if debugging {
			log.Error().Msg("Gitleaks is not enabled")
		}
		return
	}

	backendUrl, _ := Custom.GetGitleaksConfig(Custom.ConfigUrl)

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
	requestUserAgent := Custom.UserAgentPrefix + "/" + Version

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBuffer(requestData))
	req.Header.Set("User-Agent", requestUserAgent)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

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
	if gitConfig, isGitConfigRespond := data[responseStringGitConfig].(map[string]interface{}); isGitConfigRespond {
		log.Debug().Interface("Body.Data."+responseStringGitConfig, gitConfig).Msg("Response")
		for k, v := range gitConfig {
			Custom.SetGitleaksConfig(k, fmt.Sprintf("%v", v))
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
	OrganizationName, _ := Custom.GetLocalOrganizationName()
	RepositoryName, _ := Custom.GetLocalRepositoryName()
	BranchName, _ := Custom.GetHeadBranchName()
	AuthorName, _ := Custom.GetUserName()
	AuthorEmail, _ := Custom.GetUserEmail()
	CommitHash, _ := Custom.GetHeadCommitHash()
	CommitTimestamp, _ := Custom.GetHeadCommitTimestamp()

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
