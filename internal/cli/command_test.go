package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const findingsBody = `[{"component":{"uuid":"c1","group":"org","name":"lib","version":"2.0"},"vulnerability":{"uuid":"vuln-1","vulnId":"CVE-2024-0001","source":"NVD"},"analysis":{"state":"RESOLVED","isSuppressed":false}}]`

func fakeDependencyTrack(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != "test-key" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/api/v1/vulnerability/source/NVD/vuln/CVE-2024-0001":
			_, _ = writer.Write([]byte(`{"uuid":"vuln-1","vulnId":"CVE-2024-0001","source":"NVD","patchedVersions":"2.1"}`))
		case "/api/v1/vulnerability/source/NVD/vuln/CVE-2024-0001/projects":
			_, _ = writer.Write([]byte(`[{"uuid":"proj-a","name":"alpha","version":"1.0"}]`))
		case "/api/v1/finding/project/proj-a":
			_, _ = writer.Write([]byte(findingsBody))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func runCommand(t *testing.T, arguments ...string) (string, string, error) {
	t.Helper()
	command := NewRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(arguments)
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return path
}

func TestCommandWritesCSV(t *testing.T) {
	t.Setenv("DTRACK_URL", "")
	t.Setenv("DTRACK_API_KEY", "")
	server := fakeDependencyTrack(t)
	envFile := writeEnv(t, "DTRACK_URL="+server.URL+"\nDTRACK_API_KEY=test-key\n")

	stdout, stderr, err := runCommand(t, "--env-file", envFile, "cve-2024-0001", "CVE-2024-0999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "CVE,affected,patched,fix_available,affected_components,patched_components,patched_versions\n" +
		"CVE-2024-0001,yes,yes,yes,,alpha@1.0:org/lib@2.0,2.1\n" +
		"CVE-2024-0999,no,no,no,,,\n"
	if stdout != want {
		t.Fatalf("got:\n%s\nwant:\n%s", stdout, want)
	}
	if !strings.Contains(stderr, "CVE-2024-0999 is unknown") {
		t.Fatalf("expected a warning about the unknown CVE, got %q", stderr)
	}
}

func TestCommandWritesOutputFileFromStdinList(t *testing.T) {
	t.Setenv("DTRACK_URL", "")
	t.Setenv("DTRACK_API_KEY", "")
	server := fakeDependencyTrack(t)
	envFile := writeEnv(t, "DTRACK_URL="+server.URL+"\nDTRACK_API_KEY=test-key\n")
	outputFile := filepath.Join(t.TempDir(), "report.csv")

	command := NewRootCommand()
	command.SetIn(strings.NewReader("CVE-2024-0001\n"))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"--env-file", envFile, "-f", "-", "-o", outputFile})
	err := command.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(content), "CVE-2024-0001,yes,yes,yes") {
		t.Fatalf("unexpected report: %s", content)
	}
}

func TestCommandFailures(t *testing.T) {
	server := fakeDependencyTrack(t)
	testCases := []struct {
		name        string
		environment map[string]string
		arguments   []string
	}{
		{name: "no cves", environment: map[string]string{"DTRACK_URL": server.URL, "DTRACK_API_KEY": "test-key"}},
		{name: "invalid cve", environment: map[string]string{"DTRACK_URL": server.URL, "DTRACK_API_KEY": "test-key"}, arguments: []string{"not-a-cve"}},
		{name: "no api key", environment: map[string]string{"DTRACK_URL": server.URL}, arguments: []string{"CVE-2024-0001"}},
		{name: "wrong api key", environment: map[string]string{"DTRACK_URL": server.URL, "DTRACK_API_KEY": "wrong"}, arguments: []string{"CVE-2024-0001"}},
		{name: "missing cve file", environment: map[string]string{"DTRACK_URL": server.URL, "DTRACK_API_KEY": "test-key"}, arguments: []string{"-f", "/nonexistent/cves.txt"}},
		{name: "required env file missing", environment: map[string]string{"DTRACK_URL": server.URL, "DTRACK_API_KEY": "test-key"}, arguments: []string{"--env-file", "/nonexistent/.env", "CVE-2024-0001"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("DTRACK_URL", "")
			t.Setenv("DTRACK_API_KEY", "")
			for name, value := range testCase.environment {
				t.Setenv(name, value)
			}
			arguments := append([]string{"--env-file", filepath.Join(t.TempDir(), "absent.env")}, testCase.arguments...)
			if strings.Contains(strings.Join(testCase.arguments, " "), "--env-file") {
				arguments = testCase.arguments
			}
			_, _, err := runCommand(t, arguments...)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
