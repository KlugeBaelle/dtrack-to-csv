// Package assessment decides whether a CVE affects the portfolio and whether it has been dealt with.
package assessment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/dtrack"
)

var resolvedStates = map[string]bool{
	"RESOLVED":       true,
	"FALSE_POSITIVE": true,
	"NOT_AFFECTED":   true,
}

// Source provides the Dependency-Track data an assessment is built from.
type Source interface {
	FindVulnerability(ctx context.Context, source string, vulnerabilityID string) (dtrack.Vulnerability, error)
	ListAffectedProjects(ctx context.Context, source string, vulnerabilityID string) ([]dtrack.AffectedProject, error)
	ListProjectFindings(ctx context.Context, projectUUID string) ([]dtrack.Finding, error)
}

// Result is the assessment of a single CVE.
//
// Affected means at least one component is matched to the CVE. Patched means
// the CVE is affected and every matched finding is triaged as resolved,
// false positive, not affected or suppressed. AffectedComponents lists the
// still-open components, PatchedComponents the triaged ones.
type Result struct {
	CVE                    string
	KnownToDependencyTrack bool
	Affected               bool
	Patched                bool
	FixAvailable           bool
	PatchedVersions        []string
	AffectedComponents     []string
	PatchedComponents      []string
}

// Assessor builds Results and caches project findings between CVEs.
type Assessor struct {
	source               Source
	vulnerabilitySources []string
	findingsByProject    map[string][]dtrack.Finding
}

// NewAssessor creates an Assessor that looks a CVE up in each of the given
// Dependency-Track vulnerability sources (for example NVD, GITHUB, OSV).
func NewAssessor(source Source, vulnerabilitySources []string) *Assessor {
	return &Assessor{
		source:               source,
		vulnerabilitySources: vulnerabilitySources,
		findingsByProject:    make(map[string][]dtrack.Finding),
	}
}

// Assess evaluates one CVE.
func (assessor *Assessor) Assess(ctx context.Context, cve string) (Result, error) {
	vulnerabilities, err := assessor.findVulnerabilities(ctx, cve)
	if err != nil {
		return Result{}, err
	}
	result := Result{CVE: cve}
	if len(vulnerabilities) == 0 {
		return result, nil
	}
	result.KnownToDependencyTrack = true

	unresolved := make(map[string]bool)
	resolved := make(map[string]bool)
	patchedVersions := make(map[string]bool)
	for _, vulnerability := range vulnerabilities {
		versions := strings.TrimSpace(vulnerability.PatchedVersions)
		if versions != "" {
			patchedVersions[versions] = true
		}
		err = assessor.collectComponents(ctx, vulnerability, unresolved, resolved)
		if err != nil {
			return Result{}, err
		}
	}

	result.AffectedComponents = sortedKeys(unresolved)
	result.PatchedComponents = sortedKeys(resolved)
	result.PatchedVersions = sortedKeys(patchedVersions)
	result.FixAvailable = len(result.PatchedVersions) > 0
	result.Affected = len(unresolved)+len(resolved) > 0
	result.Patched = result.Affected && len(unresolved) == 0
	return result, nil
}

func (assessor *Assessor) findVulnerabilities(ctx context.Context, cve string) ([]dtrack.Vulnerability, error) {
	var vulnerabilities []dtrack.Vulnerability
	for _, source := range assessor.vulnerabilitySources {
		vulnerability, err := assessor.source.FindVulnerability(ctx, source, cve)
		if errors.Is(err, dtrack.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("assess %s: %w", cve, err)
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return vulnerabilities, nil
}

func (assessor *Assessor) collectComponents(ctx context.Context, vulnerability dtrack.Vulnerability, unresolved map[string]bool, resolved map[string]bool) error {
	projects, err := assessor.source.ListAffectedProjects(ctx, vulnerability.Source, vulnerability.VulnID)
	if err != nil {
		return fmt.Errorf("assess %s: %w", vulnerability.VulnID, err)
	}
	for _, project := range projects {
		findings, err := assessor.projectFindings(ctx, project.UUID)
		if err != nil {
			return fmt.Errorf("assess %s: %w", vulnerability.VulnID, err)
		}
		matched := 0
		for _, finding := range findings {
			if finding.Vulnerability.UUID != vulnerability.UUID {
				continue
			}
			matched++
			label := projectLabel(project) + ":" + componentLabel(finding.Component)
			if isResolved(finding.Analysis) {
				resolved[label] = true
				continue
			}
			unresolved[label] = true
		}
		if matched > 0 {
			continue
		}
		// DT reports the project as affected but lists no finding for it,
		// so the component is treated as open rather than silently dropped.
		for _, componentUUID := range project.AffectedComponentUUIDs {
			unresolved[projectLabel(project)+":"+componentUUID] = true
		}
	}
	return nil
}

func (assessor *Assessor) projectFindings(ctx context.Context, projectUUID string) ([]dtrack.Finding, error) {
	cached, found := assessor.findingsByProject[projectUUID]
	if found {
		return cached, nil
	}
	findings, err := assessor.source.ListProjectFindings(ctx, projectUUID)
	if err != nil {
		return nil, err
	}
	assessor.findingsByProject[projectUUID] = findings
	return findings, nil
}

func isResolved(analysis dtrack.FindingAnalysis) bool {
	return analysis.IsSuppressed || resolvedStates[analysis.State]
}

func projectLabel(project dtrack.AffectedProject) string {
	return withVersion(project.Name, project.Version)
}

func componentLabel(component dtrack.FindingComponent) string {
	name := component.Name
	if component.Group != "" {
		name = component.Group + "/" + component.Name
	}
	return withVersion(name, component.Version)
}

func withVersion(name string, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
