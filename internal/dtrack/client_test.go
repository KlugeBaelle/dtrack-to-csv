package dtrack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc, options ...Option) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+"/", "secret-key", options...)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestNewClientValidation(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		apiKey  string
		options []Option
	}{
		{name: "empty api key", baseURL: "https://dt.example", apiKey: ""},
		{name: "missing scheme", baseURL: "dt.example", apiKey: "key"},
		{name: "unsupported scheme", baseURL: "ftp://dt.example", apiKey: "key"},
		{name: "missing host", baseURL: "https://", apiKey: "key"},
		{name: "invalid page size", baseURL: "https://dt.example", apiKey: "key", options: []Option{WithPageSize(0)}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewClient(testCase.baseURL, testCase.apiKey, testCase.options...)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestFindVulnerability(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Api-Key") != "secret-key" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path != "/api/v1/vulnerability/source/NVD/vuln/CVE-2024-1" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = writer.Write([]byte(`{"uuid":"u1","vulnId":"CVE-2024-1","source":"NVD","patchedVersions":"1.2.3","cwes":[{"cweId":79,"name":"XSS"}]}`))
	})

	vulnerability, err := client.FindVulnerability(context.Background(), "NVD", "CVE-2024-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulnerability.UUID != "u1" || vulnerability.PatchedVersions != "1.2.3" {
		t.Fatalf("unexpected vulnerability: %+v", vulnerability)
	}

	_, err = client.FindVulnerability(context.Background(), "NVD", "CVE-2024-2")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestErrorPaths(t *testing.T) {
	testCases := []struct {
		name         string
		handler      http.HandlerFunc
		wantStatus   int
		wantNotFound bool
	}{
		{
			name:       "unauthorized",
			handler:    func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusUnauthorized) },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "forbidden",
			handler:    func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusForbidden) },
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "server error",
			handler:    func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusInternalServerError) },
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "redirect is not followed",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, "http://127.0.0.1:1/elsewhere", http.StatusFound)
			},
			wantStatus: http.StatusFound,
		},
		{
			name:         "not found",
			handler:      func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNotFound) },
			wantNotFound: true,
		},
		{
			name:    "invalid json",
			handler: func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte(`{not json`)) },
		},
		{
			name:    "wrong json shape",
			handler: func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte(`"a string"`)) },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestClient(t, testCase.handler)
			_, err := client.FindVulnerability(context.Background(), "NVD", "CVE-2024-1")
			if err == nil {
				t.Fatal("expected an error")
			}
			if testCase.wantNotFound && !errors.Is(err, ErrNotFound) {
				t.Fatalf("want ErrNotFound, got %v", err)
			}
			if testCase.wantStatus != 0 {
				var statusError *StatusError
				if !errors.As(err, &statusError) || statusError.StatusCode != testCase.wantStatus {
					t.Fatalf("want status %d, got %v", testCase.wantStatus, err)
				}
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{}`))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.FindVulnerability(ctx, "NVD", "CVE-2024-1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func servePages(total int) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		pageNumber, _ := strconv.Atoi(request.URL.Query().Get("pageNumber"))
		pageSize, _ := strconv.Atoi(request.URL.Query().Get("pageSize"))
		start := (pageNumber - 1) * pageSize
		var projects []AffectedProject
		for index := start; index < start+pageSize && index < total; index++ {
			projects = append(projects, AffectedProject{UUID: "p" + strconv.Itoa(index)})
		}
		_ = json.NewEncoder(writer).Encode(projects)
	}
}

func TestListAffectedProjectsPagination(t *testing.T) {
	testCases := []struct {
		name  string
		total int
	}{
		{name: "empty", total: 0},
		{name: "single partial page", total: 2},
		{name: "exact page boundary", total: 6},
		{name: "several pages", total: 7},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestClient(t, servePages(testCase.total), WithPageSize(3))
			projects, err := client.ListAffectedProjects(context.Background(), "NVD", "CVE-2024-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(projects) != testCase.total {
				t.Fatalf("got %d projects, want %d", len(projects), testCase.total)
			}
		})
	}
}

func TestListAffectedProjectsServerIgnoresPagination(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode([]AffectedProject{{UUID: "a"}, {UUID: "b"}, {UUID: "c"}, {UUID: "d"}})
	}, WithPageSize(3))
	projects, err := client.ListAffectedProjects(context.Background(), "NVD", "CVE-2024-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 4 {
		t.Fatalf("got %d projects, want 4", len(projects))
	}
}

func TestListAffectedProjectsNotFoundIsEmpty(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})
	projects, err := client.ListAffectedProjects(context.Background(), "NVD", "CVE-2024-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("want no projects, got %d", len(projects))
	}
}

func TestListAffectedProjectsFailsOnSecondPage(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("pageNumber") == "2" {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(writer).Encode([]AffectedProject{{UUID: "a"}, {UUID: "b"}})
	}, WithPageSize(2))
	_, err := client.ListAffectedProjects(context.Background(), "NVD", "CVE-2024-1")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestListProjectFindingsIncludesSuppressed(t *testing.T) {
	client := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/finding/project/proj-1" || request.URL.Query().Get("suppressed") != "true" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = writer.Write([]byte(`[{"component":{"uuid":"c1","group":"g","name":"n","version":"1"},"vulnerability":{"uuid":"v1","vulnId":"CVE-2024-1","source":"NVD"},"analysis":{"state":"RESOLVED","isSuppressed":true}}]`))
	})
	findings, err := client.ListProjectFindings(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || !findings[0].Analysis.IsSuppressed || findings[0].Component.Name != "n" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
