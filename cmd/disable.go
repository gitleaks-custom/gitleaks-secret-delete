package cmd

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	Custom "github.com/zricethezav/gitleaks/v8/custom"
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
	if Custom.GetGitleaksConfigBoolean(Custom.ConfigDebug) {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Remove Config in .git/config : Gitleaks.enable to false
	// Custom.SetGitleaksConfig("enable", "false")
	Custom.DeleteGitleaksConfig(Custom.ConfigEnable)

	// Remove Config in .git/config : Gitleaks.url to null
	// Custom.SetGitleaksConfig("url", "")
	Custom.DeleteGitleaksConfig(Custom.ConfigUrl)

	// Remove Config in .git/config : Gitleaks.debug to false
	// Custom.SetGitleaksConfig("debug", "false")
	Custom.DeleteGitleaksConfig(Custom.ConfigDebug)

	// Remove Script in .git/hooks/pre-commit
	Custom.DisableGitHooks(Custom.PreCommitScriptPath, Custom.PreCommitScript)

	// Remove Script in .git/hooks/post-commit
	Custom.DisableGitHooks(Custom.PostCommitScriptPath, Custom.PostCommitScript)

	log.Debug().Msg("Gitleaks Disabled")
}
