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
	if ucmp.GetGitleaksConfigBoolean(ucmp.ConfigDebug) {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Remove Gitleaks.enable in .git/config
	ucmp.DeleteGitleaksConfig(ucmp.ConfigEnable)

	// Remove Gitleaks.url in .git/config
	// Custom.SetGitleaksConfig("url", "")
	ucmp.DeleteGitleaksConfig(ucmp.ConfigUrl)

	// Remove Gitleaks.debug in .git/config
	ucmp.DeleteGitleaksConfig(ucmp.ConfigDebug)

	// Remove Gitleaks.scanned in .git/config
	ucmp.DeleteGitleaksConfig(ucmp.ConfigScanned)

	// Remove Script in .git/hooks/pre-commit
	ucmp.DisableGitHooks(ucmp.PreCommitScriptPath, ucmp.PreCommitScript)

	// Remove Script in .git/hooks/post-commit
	ucmp.DisableGitHooks(ucmp.PostCommitScriptPath, ucmp.PostCommitScript)

	log.Debug().Msg("Gitleaks Disabled")
}
