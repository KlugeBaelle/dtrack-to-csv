// Package dtrack is a minimal client for the Dependency-Track v5 REST API (v1 endpoints).
package dtrack

// Vulnerability is a vulnerability record stored in Dependency-Track.
type Vulnerability struct {
	UUID            string `json:"uuid"`
	VulnID          string `json:"vulnId"`
	Source          string `json:"source"`
	PatchedVersions string `json:"patchedVersions"`
}

// AffectedProject is a project that contains components matched to a vulnerability.
type AffectedProject struct {
	UUID                   string   `json:"uuid"`
	Name                   string   `json:"name"`
	Version                string   `json:"version"`
	Active                 bool     `json:"active"`
	AffectedComponentUUIDs []string `json:"affectedComponentUuids"`
}

// Finding links a component to a vulnerability together with its analysis.
type Finding struct {
	Component     FindingComponent     `json:"component"`
	Vulnerability FindingVulnerability `json:"vulnerability"`
	Analysis      FindingAnalysis      `json:"analysis"`
}

// FindingComponent identifies the component a finding was raised for.
type FindingComponent struct {
	UUID    string `json:"uuid"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FindingVulnerability identifies the vulnerability a finding refers to.
type FindingVulnerability struct {
	UUID   string `json:"uuid"`
	VulnID string `json:"vulnId"`
	Source string `json:"source"`
}

// FindingAnalysis is the triage state of a finding.
type FindingAnalysis struct {
	State        string `json:"state"`
	IsSuppressed bool   `json:"isSuppressed"`
}
