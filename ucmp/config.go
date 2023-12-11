package ucmp

import (
	"os"
	"path"
	"strconv"
	"sync"
)

// debug
// enable
// scanned
// url

type AUDIT_CONFIG string

const (
	// Global Scope
	AUDIT_CONFIG_KEY_URL    AUDIT_CONFIG = "url"    // string
	AUDIT_CONFIG_KEY_ENABLE AUDIT_CONFIG = "enable" // boolean

	// Local Scope
	AUDIT_CONFIG_KEY_DEBUG   AUDIT_CONFIG = "debug"   // boolean
	AUDIT_CONFIG_KEY_SCANNED AUDIT_CONFIG = "scanned" // boolean
)

var callOnceAuditInstance sync.Once // Support Singleton

type AuditConfig struct {
	Global map[AUDIT_CONFIG]interface{}
	Local  map[AUDIT_CONFIG]interface{}
}

var auditConfigInstance *AuditConfig

func GetAuditConfigInstance() *AuditConfig {
	if auditConfigInstance == nil { // Singleton instance
		callOnceAuditInstance.Do(func() {
			auditConfigInstance = &AuditConfig{
				Global: make(map[AUDIT_CONFIG]interface{}),
				Local:  make(map[AUDIT_CONFIG]interface{}),
			}
		})
	}

	auditConfigInstance.init()
	return auditConfigInstance
}

func (c *AuditConfig) init() {
	if value, err := getAuditConfigString(GIT_SCOPE_GLOBAL, AUDIT_CONFIG_KEY_URL); err == nil {
		c.Global[AUDIT_CONFIG_KEY_URL] = value
	}

	// Global Scope Enable flags *
	if value, err := getAuditConfigBoolean(GIT_SCOPE_GLOBAL, AUDIT_CONFIG_KEY_ENABLE); err == nil {
		c.Global[AUDIT_CONFIG_KEY_ENABLE] = value
	}

	// Local Scope Enable flags * - Need per-repository controls
	if value, err := getAuditConfigBoolean(GIT_SCOPE_LOCAL, AUDIT_CONFIG_KEY_ENABLE); err == nil {
		c.Local[AUDIT_CONFIG_KEY_ENABLE] = value
	}

	if value, err := getAuditConfigBoolean(GIT_SCOPE_LOCAL, AUDIT_CONFIG_KEY_DEBUG); err == nil {
		c.Local[AUDIT_CONFIG_KEY_DEBUG] = value
	}

	if value, err := getAuditConfigBoolean(GIT_SCOPE_LOCAL, AUDIT_CONFIG_KEY_SCANNED); err == nil {
		c.Local[AUDIT_CONFIG_KEY_SCANNED] = value
	}
}

func (c *AuditConfig) SetAuditConfig(scope GitScope, key AUDIT_CONFIG, value interface{}) {
	switch v := value.(type) {
	case string:
		_, err := setAuditConfig(scope, string(key), v)
		if err != nil {
			return
		}
	case bool:
		_, err := setAuditConfig(scope, string(key), strconv.FormatBool(v)) // Type casting boolean to string
		if err != nil {
			return
		}
	default:
		return
	}

	switch scope {
	case GIT_SCOPE_LOCAL:
		c.Local[key] = value
	case GIT_SCOPE_GLOBAL:
		c.Global[key] = value
	}
}

func (c *AuditConfig) SetAuditConfigUnsafe(key string, value string) {
	_, err := setAuditConfig(GIT_SCOPE_LOCAL, key, value)
	if err != nil {
		return
	}
}

// Unset Config value from git config file and auditConfigInstance
func (c *AuditConfig) UnsetAuditConfig(scope GitScope, key AUDIT_CONFIG) {
	_, err := deleteAuditConfig(scope, string(key))
	if err != nil {
		// When unset config error, If config value still exists, Then set to "" (empty string)
		if val, _ := getGitConfig(scope, string(key)); val != "" {
			c.SetAuditConfig(scope, key, "")
		}
	}

	switch scope {
	case GIT_SCOPE_LOCAL:
		delete(c.Local, key)
	case GIT_SCOPE_GLOBAL:
		delete(c.Global, key)
	}
}

func (c *AuditConfig) GetAuditConfigString(key AUDIT_CONFIG) string {
	if value, ok := c.Local[key]; ok {
		if stringValue, ok := value.(string); ok {
			return stringValue
		}
	}

	if value, ok := c.Global[key]; ok {
		if stringValue, ok := value.(string); ok {
			return stringValue
		}
	}

	return ""
}

func (c *AuditConfig) GetAuditConfigBoolean(key AUDIT_CONFIG) bool {
	if value, ok := c.Local[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}

	if value, ok := c.Global[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}

	return false
}

func (c *AuditConfig) SetGlobalHooksPath() error {
	homeDir, _ := os.UserHomeDir()
	hooksPath := path.Join(homeDir, CoreHooksPath)

	_, err := execGitCommand("config", "--global", "core.hooksPath", hooksPath)
	if err != nil {
		return err
	}
	return nil
}

func (c *AuditConfig) UnsetGlobalHooksPath() error {
	_, err := execGitCommand("config", "--global", "--unset", "core.hooksPath")
	if err != nil {
		return err
	}
	return nil
}

func (c *AuditConfig) RetrieveRepositoryInfo() map[string]string {
	req := make(map[string]string)

	// Key Name must be the same as AuditRequest
	req["organizationName"] = getLocalOrganizationName()
	req["repositoryName"] = getLocalRepositoryName()
	req["branchName"] = getHeadBranchName()
	req["authorName"] = getUserName()
	req["authorEmail"] = getUserEmail()
	req["commitHash"] = getHeadCommitHash()
	req["commitTimestamp"] = getHeadCommitTimestamp()

	return req
}
