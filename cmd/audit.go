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
	// If Error occurs not throwing exceptions.
	defer func() {
		recover()
		return
	}()

	auditConfig := ucmp.GetAuditConfigInstance()

	if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if !auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_ENABLE) {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Audit is not enabled")
		}
		return // Exit the program, if 'enable' is false
	}

	if !auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_SCANNED) {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Staged files are not scanned")
		}
		return // Exit the program, if 'scanned' is false (Check file: protect.go)
	}

	// Unset 'scanned' for next scan check.
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_LOCAL, ucmp.AUDIT_CONFIG_KEY_SCANNED)

	authInstance := ucmp.GetAuthenticationInstance()
	if !authInstance.CheckValidEmail() {
		log.Error().Msg(fmt.Sprintf("Email is not one of valid domains: %s", authInstance.GetValidDomainList()))
		// Error message is "Email is not one of valid domains: lguplus.co.kr, lguplus.partners.co.kr"
		return
	}

	log.Debug().Str("Url", auditConfig.GetAuditConfigString(ucmp.AUDIT_CONFIG_KEY_URL)).Msg("Request")

	u, err := url.Parse(auditConfig.GetAuditConfigString(ucmp.AUDIT_CONFIG_KEY_URL))
	// net/url Parsing Error
	if err != nil {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Error Parsing URL ," + err.Error())
		}
		panic(err)
	}

	// Request Handling
	requestData, _ := json.Marshal(auditConfig.RetrieveRepositoryInfo())

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBuffer(requestData))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", authInstance.UserAgent+"/"+Version)
	req.SetBasicAuth(Version, authInstance.BinaryCheckSum)

	log.Debug().RawJSON("Body", requestData).Msg("Request")

	client := &http.Client{}
	resp, err := client.Do(req)
	// net/http client Error - Request 오류 시 백엔드 통신 X
	if err != nil {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Http Request Error, " + err.Error())
		}
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Msg("Error while reading response body")
			return
		}
		log.Error().Msg(fmt.Sprintf("Error from server [%s] %s", resp.Status, string(bodyBytes)))
		panic(resp.Status)
	}
	// Response Handling
	response, _ := io.ReadAll(resp.Body)

	// Response Handling
	var responseData AuditResponse
	log.Debug().RawJSON("Body", response).Msg("Response")
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
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

	if gitConfig, isGitConfigRespond := data[responseStringGitConfig].(map[string]interface{}); isGitConfigRespond {
		log.Debug().Interface("Body.Data."+responseStringGitConfig, gitConfig).Msg("Response")
		for k, v := range gitConfig {
			auditConfig.SetAuditConfigUnsafe(k, fmt.Sprintf("%v", v))
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
