package cmd

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/ucmp"
	"os"
)

func init() {
	enableCmd.Flags().String(string(ucmp.AUDIT_CONFIG_KEY_URL), "", "Audit Backend Url (Default : https://audit.ucmp.uplus.co.kr/gitleaks/)")
	enableCmd.Flags().Bool(string(ucmp.AUDIT_CONFIG_KEY_DEBUG), false, "Enable debug output")
	enableCmd.MarkFlagRequired(string(ucmp.AUDIT_CONFIG_KEY_URL))
	rootCmd.AddCommand(enableCmd)
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable gitleaks in pre-commit script",
	Run:   runEnable,
}

func runEnable(cmd *cobra.Command, args []string) {
	auditConfig := ucmp.GetAuditConfigInstance()

	// 1. Enable Global Git Hooks (pre-commit, post-commit)
	err := auditConfig.SetGlobalHooksPath()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to set global hooks path")
		os.Exit(-1)
	}

	// 2. Setting Url and other flags (debug, enable)
	url, _ := cmd.Flags().GetString(string(ucmp.AUDIT_CONFIG_KEY_URL))
	auditConfig.SetAuditConfig(ucmp.GIT_SCOPE_GLOBAL, ucmp.AUDIT_CONFIG_KEY_URL, url) // Check Global Git Config

	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		// If enable command with --debug flag, print the all commands logs
		auditConfig.SetAuditConfig(ucmp.GIT_SCOPE_LOCAL, ucmp.AUDIT_CONFIG_KEY_DEBUG, debug) // Check Local Git Config
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	auditConfig.SetAuditConfig(ucmp.GIT_SCOPE_GLOBAL, ucmp.AUDIT_CONFIG_KEY_ENABLE, true) // Check Global Git Config

	// Insert Script Content in $HOME/.githooks pre-commit, post-commit

	// 3. Install Global Git Hooks (pre-commit, post-commit)
	ucmp.InstallGitHookScript(ucmp.PreCommitScriptPath, ucmp.LocalPreCommitSupportScript)
	ucmp.InstallGitHookScript(ucmp.PreCommitScriptPath, ucmp.PreCommitScript)
	ucmp.InstallGitHookScript(ucmp.PostCommitScriptPath, ucmp.PostCommitScript)

	log.Debug().Msg("Gitleaks Enabled")
}
