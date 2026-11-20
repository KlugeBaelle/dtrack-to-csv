package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	testCases := []struct {
		name        string
		fileContent string
		useFile     bool
		required    bool
		environment map[string]string
		urlOverride string
		want        Config
		wantError   bool
		missingFile bool
	}{
		{
			name:        "values from env file",
			fileContent: "DTRACK_URL=https://dt.example\nDTRACK_API_KEY=file-key\n",
			useFile:     true,
			want:        Config{URL: "https://dt.example", APIKey: "file-key"},
		},
		{
			name:        "environment beats env file",
			fileContent: "DTRACK_URL=https://dt.example\nDTRACK_API_KEY=file-key\n",
			useFile:     true,
			environment: map[string]string{"DTRACK_API_KEY": "env-key"},
			want:        Config{URL: "https://dt.example", APIKey: "env-key"},
		},
		{
			name:        "flag beats everything for the url",
			fileContent: "DTRACK_URL=https://dt.example\nDTRACK_API_KEY=file-key\n",
			useFile:     true,
			urlOverride: "https://flag.example",
			want:        Config{URL: "https://flag.example", APIKey: "file-key"},
		},
		{
			name:        "optional missing env file falls back to environment",
			missingFile: true,
			environment: map[string]string{"DTRACK_URL": "https://dt.example", "DTRACK_API_KEY": "env-key"},
			want:        Config{URL: "https://dt.example", APIKey: "env-key"},
		},
		{
			name:        "required missing env file fails",
			missingFile: true,
			required:    true,
			environment: map[string]string{"DTRACK_URL": "https://dt.example", "DTRACK_API_KEY": "env-key"},
			wantError:   true,
		},
		{
			name:        "missing api key",
			fileContent: "DTRACK_URL=https://dt.example\n",
			useFile:     true,
			wantError:   true,
		},
		{
			name:        "missing url",
			fileContent: "DTRACK_API_KEY=file-key\n",
			useFile:     true,
			wantError:   true,
		},
		{
			name:        "malformed env file",
			fileContent: "DTRACK_URL=\"unterminated\n",
			useFile:     true,
			wantError:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(URLVariable, "")
			t.Setenv(APIKeyVariable, "")
			for name, value := range testCase.environment {
				t.Setenv(name, value)
			}
			path := filepath.Join(t.TempDir(), "absent.env")
			if testCase.useFile {
				path = writeEnvFile(t, testCase.fileContent)
			}

			got, err := Load(path, testCase.required, testCase.urlOverride)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("got %+v, want %+v", got, testCase.want)
			}
		})
	}
}
