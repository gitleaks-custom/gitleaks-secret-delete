package cmd

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/ucmp"
)

func init() {
	rootCmd.AddCommand(disableCmd)
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable gitleaks in pre-commit script",
	Run:   runDisable,
}

func runDisable(cmd *cobra.Command, args []string) {
	auditConfig := ucmp.GetAuditConfigInstance()

	if auditConfig.GetAuditConfigBoolean(ucmp.AUDIT_CONFIG_KEY_DEBUG) {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 1. Disable Global Git Hooks (pre-commit, post-commit)
	_ = auditConfig.UnsetGlobalHooksPath()

	// 2. Unsetting Url and other flags (debug, enable)
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_GLOBAL, ucmp.AUDIT_CONFIG_KEY_URL)
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_GLOBAL, ucmp.AUDIT_CONFIG_KEY_ENABLE)
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_GLOBAL, ucmp.AUDIT_CONFIG_KEY_TIMEOUT)
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_LOCAL, ucmp.AUDIT_CONFIG_KEY_DEBUG)
	auditConfig.UnsetAuditConfig(ucmp.GIT_SCOPE_LOCAL, ucmp.AUDIT_CONFIG_KEY_SCANNED)

	// 3. Uninstall Global Git Hooks (pre-commit, post-commit)
	// ucmp.UninstallGitHookScript(ucmp.PreCommitScriptPath, ucmp.PreCommitScript)
	// ucmp.UninstallGitHookScript(ucmp.PreCommitScriptPath, ucmp.LocalPreCommitSupportScript)
	// ucmp.UninstallGitHookScript(ucmp.PostCommitScriptPath, ucmp.PostCommitScript)
	ucmp.RemoveGitHookScript(ucmp.PreCommitScriptPath)
	ucmp.RemoveGitHookScript(ucmp.PostCommitScriptPath)

	log.Info().Msg("Gitleaks Disabled")
}
