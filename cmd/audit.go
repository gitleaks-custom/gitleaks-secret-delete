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
	"time"
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

// Response Schema between Backend and Gitleaks cli
const (
	responseStringGitConfig = "GitConfig"
	responseStringVersion   = "Version"
	responseStringMessage   = "Message"
)

func runAudit(cmd *cobra.Command, args []string) {
	// Not throwing exceptions when error occurs
	defer func() {
		recover()
		return
	}()

	// 1. 설정 값 Validation
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

	// 2. 사용자 이메일 Validation
	authInstance := ucmp.GetAuthenticationInstance()
	if !authInstance.CheckValidEmail() {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			// "Email is not one of valid domains: lguplus.co.kr, lgupluspartners.co.kr" (See ucmp/authenticate.go )
			log.Error().Msg(fmt.Sprintf("Email is not one of valid domains: %s", authInstance.GetValidDomainList()))
		}
		return
	}

	log.Debug().Str("Url", auditConfig.GetAuditConfigString(ucmp.AUDIT_CONFIG_KEY_URL)).Msg("Request")

	// 3. 데이터 전송 준비
	requestUrl, err := url.Parse(auditConfig.GetAuditConfigString(ucmp.AUDIT_CONFIG_KEY_URL)) // (See Global Config 'Gitleaks.url')
	if err != nil {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Error Parsing URL ," + err.Error())
		}
		panic(err)
	}

	requestData, _ := json.Marshal(auditConfig.RetrieveRepositoryInfo())

	req, _ := http.NewRequest("POST", requestUrl.String(), bytes.NewBuffer(requestData))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", authInstance.UserAgent+"/"+Version)
	req.SetBasicAuth(Version, authInstance.BinaryCheckSum) // => Backend Side header "authorization: Basic {base64 encoded version:checksum}"

	log.Debug().RawJSON("Body", requestData).Msg("Request")

	// 4. Gitleaks 백엔드에 데이터 전송
	var timeout int64
	if timeout = auditConfig.GetAuditConfigInt64(ucmp.AUDIT_CONFIG_KEY_TIMEOUT); timeout == 0 {
		timeout = 5
	}
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second, // Default Timeout : 5 seconds
	}
	resp, err := client.Do(req)

	// 5. Response Handling
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

	response, _ := io.ReadAll(resp.Body)
	log.Debug().RawJSON("Body", response).Msg("Response")

	// Type casting JSON to struct
	var responseData AuditResponse
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
			log.Error().Msg("Json Unmarshal Error, " + err.Error())
		}
		panic(err)
	}

	// Type casting struct to map
	data, ok := responseData.Data.(map[string]interface{})
	if !ok {
		// Response Data type Error: Response.Data field is not map type.
		log.Fatal().Err(err).Msg("")
	}

	// Handling Response Data - responseStringGitConfig = "GitConfig"
	if gitConfig, isGitConfigRespond := data[responseStringGitConfig].(map[string]interface{}); isGitConfigRespond {
		log.Debug().Interface("Body.Data."+responseStringGitConfig, gitConfig).Msg("Response")
		for k, v := range gitConfig {
			auditConfig.SetAuditConfigUnsafe(k, fmt.Sprintf("%v", v))
		}
	}

	// Handling Response Data - responseStringVersion = "Version"
	version, isVersionRespond := data[responseStringVersion]

	// Handling Response Data - responseStringMessage = "Message"
	message, isMessageRespond := data[responseStringMessage]

	// Version Check & Print message
	if isVersionRespond && (version != Version) {
		log.Debug().Interface("Body.Data."+responseStringVersion, version).Msg("Response")
		if isMessageRespond {
			log.Debug().Interface("Body.Data."+responseStringMessage, message).Msg("Response")
			log.Info().Msgf("%s", message)
		}
	}
}
