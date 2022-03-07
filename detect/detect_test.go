package detect

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestDetectFindings(t *testing.T) {
	tests := []struct {
		cfgName          string
		opts             Options
		filePath         string
		bytes            []byte
		commit           string
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName:  "escaped_character_group",
			bytes:    []byte(`pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`),
			filePath: "tmp.go",
			expectedFindings: []report.Finding{
				{
					Description: "PyPI upload token",
					Secret:      "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Match:       "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					File:        "tmp.go",
					RuleID:      "pypi-upload-token",
					Tags:        []string{"key", "pypi"},
					StartLine:   1,
					EndLine:     1,
					StartColumn: 1,
					EndColumn:   86,
				},
			},
		},
		{
			cfgName:  "simple",
			bytes:    []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath: "tmp.go",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   1,
					EndLine:     1,
					StartColumn: 15,
					EndColumn:   34,
				},
			},
		},
		{
			cfgName:          "allow_aws_re",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:          "allow_path",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:          "allow_commit",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
			commit:           "allowthiscommit",
		},
		{
			cfgName:  "entropy_group",
			bytes:    []byte(`const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`),
			filePath: "tmp.go",
			expectedFindings: []report.Finding{
				{
					Description: "Discord API key",
					Match:       "Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					File:        "tmp.go",
					RuleID:      "discord-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   1,
					EndLine:     1,
					StartColumn: 7,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName:          "generic_with_py_path",
			bytes:            []byte(`const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:  "generic_with_py_path",
			bytes:    []byte(`const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`),
			filePath: "tmp.py",
			expectedFindings: []report.Finding{
				{
					Description: "Generic API Key",
					Match:       "Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					File:        "tmp.py",
					RuleID:      "generic-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   1,
					EndLine:     1,
					StartColumn: 22,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName:  "path_only",
			bytes:    []byte(`const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`),
			filePath: "tmp.py",
			expectedFindings: []report.Finding{
				{
					Description: "Python Files",
					Match:       "file detected: tmp.py",
					File:        "tmp.py",
					RuleID:      "python-files-only",
					Tags:        []string{},
				},
			},
		},
		{
			cfgName:          "bad_entropy_group",
			bytes:            []byte(`const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
			wantError:        fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName:          "simple",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         filepath.Join(configPath, "simple.toml"),
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:          "allow_global_aws_re",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
	}

	for _, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		viper.Unmarshal(&vc)
		cfg, err := vc.Translate()
		cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
		if tt.wantError != nil {
			if err == nil {
				t.Errorf("expected error")
			}
			assert.Equal(t, tt.wantError, err)
		}

		findings := DetectFindings(cfg, tt.bytes, tt.filePath, tt.commit)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
