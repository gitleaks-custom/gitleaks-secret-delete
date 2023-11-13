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
	auditResponseDataGitConfig = "GitConfig"
	auditResponseDataVersion   = "Version"
	auditResponseDataMessage   = "Message"
)

func runAudit(cmd *cobra.Command, args []string) {
	// 로직상 오류가 발생해도 정상 리턴
	defer func() {
		recover()
		return
	}()

	debugging := Custom.GetGitleaksConfigBoolean(Custom.ConfigDebug)
	if debugging {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	isScanned := Custom.GetGitleaksConfigBoolean(Custom.ConfigScanned)
	if !isScanned {
		if debugging {
			log.Error().Msg("Staged files are not scanned")
		}
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

	var responseData AuditResponse
	log.Debug().RawJSON("Body", response).Msg("Response")
	// Error During Json Unmarshaling - 백엔드 Response Type 변경 등
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		if debugging {
			log.Error().Msg("Json Unmarshal Error, " + err.Error())
		}
		panic(err)
	}

	responseVersion := responseData.Data.(map[string]interface{})[auditResponseDataVersion]
	if responseVersion != nil {
		log.Debug().Interface("Body.Data.Version", responseVersion).Msg("Response")
	}

	responseMessage := responseData.Data.(map[string]interface{})[auditResponseDataMessage]
	if responseMessage != nil {
		log.Debug().Interface("Body.Data.Message", responseMessage).Msg("Response")
		if responseVersion != Version {
			log.Info().Msgf("%s", responseMessage)
		}
	}

	responseGitConfig := responseData.Data.(map[string]interface{})[auditResponseDataGitConfig].(map[string]interface{})
	if responseGitConfig != nil {
		log.Debug().Interface("Body.Data.GitConfig", responseGitConfig).Msg("Response")
		for k, v := range responseGitConfig {
			Custom.SetGitleaksConfig(k, fmt.Sprintf("%v", v))
		}
	}
}

func retrieveLocalGitInfo() AuditRequest {
	OrganizationName, _ := Custom.GetLocalOrganizationName()
	RepositoryName, _ := Custom.GetLocalRepositoryName()
	BranchName, _ := Custom.GetHeadBranchName()
	AuthorName, _ := Custom.GetLocalUserName()
	AuthorEmail, _ := Custom.GetLocalUserEmail()
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
