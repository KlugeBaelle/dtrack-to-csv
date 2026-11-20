package dtrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageSize    = 100
	defaultHTTPTimeout = 30 * time.Second
	maxPages           = 1000
	maxResponseBytes   = 64 << 20
	apiKeyHeader       = "X-Api-Key"
)

// ErrNotFound is returned when Dependency-Track answers with HTTP 404.
var ErrNotFound = errors.New("not found")

// StatusError is returned for any unexpected HTTP status.
type StatusError struct {
	StatusCode int
	Path       string
}

// Error implements the error interface.
func (statusError *StatusError) Error() string {
	return fmt.Sprintf("dependency-track returned status %d for %s", statusError.StatusCode, statusError.Path)
}

// Client talks to the Dependency-Track API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	pageSize   int
}

// Option customizes a Client.
type Option func(*Client)

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

// WithPageSize sets how many items are requested per page.
func WithPageSize(pageSize int) Option {
	return func(client *Client) {
		client.pageSize = pageSize
	}
}

// NewClient creates a client for the Dependency-Track instance at baseURL.
func NewClient(baseURL string, apiKey string, options ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("api key must not be empty")
	}
	trimmedURL := strings.TrimRight(baseURL, "/")
	parsedURL, err := url.Parse(trimmedURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("base url %q must start with http:// or https://", baseURL)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("base url %q has no host", baseURL)
	}

	client := &Client{
		baseURL:    trimmedURL,
		apiKey:     apiKey,
		httpClient: newDefaultHTTPClient(),
		pageSize:   defaultPageSize,
	}
	for _, option := range options {
		option(client)
	}
	if client.pageSize < 1 {
		return nil, fmt.Errorf("page size must be positive, got %d", client.pageSize)
	}
	return client, nil
}

// The API key must never follow a redirect to another host.
func newDefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// FindVulnerability looks up a vulnerability by source (for example NVD) and ID.
// It returns ErrNotFound when Dependency-Track does not know it.
func (client *Client) FindVulnerability(ctx context.Context, source string, vulnerabilityID string) (Vulnerability, error) {
	path := vulnerabilityPath(source, vulnerabilityID)
	var vulnerability Vulnerability
	err := client.getJSON(ctx, path, nil, &vulnerability)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("find vulnerability %s/%s: %w", source, vulnerabilityID, err)
	}
	return vulnerability, nil
}

// ListAffectedProjects returns every project that contains a component matched to the vulnerability.
func (client *Client) ListAffectedProjects(ctx context.Context, source string, vulnerabilityID string) ([]AffectedProject, error) {
	path := vulnerabilityPath(source, vulnerabilityID) + "/projects"
	projects, err := fetchAllPages[AffectedProject](ctx, client, path, nil)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list projects affected by %s/%s: %w", source, vulnerabilityID, err)
	}
	return projects, nil
}

// ListProjectFindings returns all findings of a project, including suppressed ones.
func (client *Client) ListProjectFindings(ctx context.Context, projectUUID string) ([]Finding, error) {
	path := "/api/v1/finding/project/" + url.PathEscape(projectUUID)
	query := url.Values{}
	query.Set("suppressed", "true")
	findings, err := fetchAllPages[Finding](ctx, client, path, query)
	if err != nil {
		return nil, fmt.Errorf("list findings of project %s: %w", projectUUID, err)
	}
	return findings, nil
}

func vulnerabilityPath(source string, vulnerabilityID string) string {
	return "/api/v1/vulnerability/source/" + url.PathEscape(source) + "/vuln/" + url.PathEscape(vulnerabilityID)
}

// A page that is not exactly pageSize long ends the listing. That also covers
// servers that ignore pagination and return everything at once.
func fetchAllPages[Item any](ctx context.Context, client *Client, path string, query url.Values) ([]Item, error) {
	var items []Item
	for pageNumber := 1; pageNumber <= maxPages; pageNumber++ {
		pageQuery := url.Values{}
		for key, values := range query {
			pageQuery[key] = values
		}
		pageQuery.Set("pageNumber", strconv.Itoa(pageNumber))
		pageQuery.Set("pageSize", strconv.Itoa(client.pageSize))

		var page []Item
		err := client.getJSON(ctx, path, pageQuery, &page)
		if err != nil {
			return nil, err
		}
		items = append(items, page...)
		if len(page) != client.pageSize {
			return items, nil
		}
	}
	return nil, fmt.Errorf("more than %d pages returned for %s", maxPages, path)
}

func (client *Client) getJSON(ctx context.Context, path string, query url.Values, target any) error {
	endpoint := client.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request for %s: %w", path, err)
	}
	request.Header.Set(apiKeyHeader, client.apiKey)
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("get %s: %w", path, err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return fmt.Errorf("get %s: %w", path, ErrNotFound)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &StatusError{StatusCode: response.StatusCode, Path: path}
	}

	err = json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(target)
	if err != nil {
		return fmt.Errorf("decode response of %s: %w", path, err)
	}
	return nil
}
