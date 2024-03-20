package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func UcmpAWSSecretKey() *config.Rule {
	r := config.Rule{
		RuleID:      "aws-secret-access-key",
		Description: "AWS Secret Access Key", // [0-9a-z\-_.=]
		Regex: generateSemiGenericRegex([]string{
			"secret",
			"access",
			"token",
			"key",
		}, `[0-9a-z+\/]{40}`, true),
		// Regex: regexp.MustCompile(`[a-zA-Z0-9+\/]{40}`),
		Keywords: []string{
			"secret",
			"access",
			"token",
			"key",
		},
		Entropy: 3.5,
		Allowlist: config.Allowlist{
			StopWords: DefaultStopWords,
		},
	}

	tps := []string{
		`aws_secret_access_token = ` + secrets.NewSecret(`[0-9a-zA-Z+\/]{40}`),
	}

	return validate(r, tps, nil)
}

func UcmpGoogleOAuthCliendId() *config.Rule {
	r := config.Rule{
		RuleID:      "google-oauth-client-id",
		Description: "Google OAuth Client ID",
		// Regex:       regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		Regex: generateUniqueTokenRegex(`[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com`, true),
	}

	tps := []string{
		"1234567890-" + secrets.NewSecret(`[0-9A-Za-z_]{32}`) + ".apps.googleusercontent.com",
	}

	return validate(r, tps, nil)
}

func UcmpGoogleOAuthClientSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "google-oauth-client-secret",
		Description: "Google OAuth Client Secret",
		// Regex:       regexp.MustCompile(`GOCSPX-[0-9A-Za-z\-_]{20,40}`),
		Regex: generateUniqueTokenRegex(`GOCSPX-[0-9a-z\-_]{20,40}`, true),
	}

	tps := []string{
		"GOCSPX-" + secrets.NewSecret(`[0-9A-Za-z\_-]{20,40}`),
	}

	return validate(r, tps, nil)
}

// func UcmpFirebaseCloudMessagingServerKey() *config.Rule {
// 	//
// 	r := config.Rule{
// 		RuleID:      "firebase-cloud-messaging-server-key",
// 		Description: "Firebase Cloud Messaging Server Key",
// 		Regex:       regexp.MustCompile("[^A-Za-z0-9+\\/]{0,1}AAAA[A-Za-z0-9]{7}:[A-Za-z0-9-_]{140}[^A-Za-z0-9+\\/]{0,1}"),
// 	}
// 	tps := []string{
// 		"AAAA" + secrets.NewSecret(`[A-Za-z0-9]{7}`) + ":" + secrets.NewSecret(`[A-Za-z0-9-_]{140}`),
// 	}
//
// 	return validate(r, tps, nil)
// }
