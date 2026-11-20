package assessment

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/dtrack"
)

type fakeSource struct {
	vulnerabilities    map[string]dtrack.Vulnerability
	projects           map[string][]dtrack.AffectedProject
	findings           map[string][]dtrack.Finding
	findingsError      error
	projectsError      error
	vulnerabilityError error
	findingCalls       map[string]int
}

func (source *fakeSource) FindVulnerability(_ context.Context, sourceName string, vulnerabilityID string) (dtrack.Vulnerability, error) {
	if source.vulnerabilityError != nil {
		return dtrack.Vulnerability{}, source.vulnerabilityError
	}
	vulnerability, found := source.vulnerabilities[sourceName+"/"+vulnerabilityID]
	if !found {
		return dtrack.Vulnerability{}, dtrack.ErrNotFound
	}
	return vulnerability, nil
}

func (source *fakeSource) ListAffectedProjects(_ context.Context, sourceName string, vulnerabilityID string) ([]dtrack.AffectedProject, error) {
	if source.projectsError != nil {
		return nil, source.projectsError
	}
	return source.projects[sourceName+"/"+vulnerabilityID], nil
}

func (source *fakeSource) ListProjectFindings(_ context.Context, projectUUID string) ([]dtrack.Finding, error) {
	source.findingCalls[projectUUID]++
	if source.findingsError != nil {
		return nil, source.findingsError
	}
	return source.findings[projectUUID], nil
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		vulnerabilities: map[string]dtrack.Vulnerability{
			"NVD/CVE-2024-1": {UUID: "vuln-1", VulnID: "CVE-2024-1", Source: "NVD"},
		},
		projects: map[string][]dtrack.AffectedProject{
			"NVD/CVE-2024-1": {{UUID: "proj-a", Name: "alpha", Version: "1.0"}},
		},
		findings:     map[string][]dtrack.Finding{},
		findingCalls: map[string]int{},
	}
}

func finding(vulnerabilityUUID string, name string, state string, suppressed bool) dtrack.Finding {
	return dtrack.Finding{
		Component:     dtrack.FindingComponent{UUID: "c-" + name, Group: "org", Name: name, Version: "2.0"},
		Vulnerability: dtrack.FindingVulnerability{UUID: vulnerabilityUUID},
		Analysis:      dtrack.FindingAnalysis{State: state, IsSuppressed: suppressed},
	}
}

func TestAssess(t *testing.T) {
	testCases := []struct {
		name             string
		prepare          func(*fakeSource)
		wantKnown        bool
		wantAffected     bool
		wantPatched      bool
		wantFix          bool
		wantAffectedList []string
		wantPatchedList  []string
	}{
		{
			name:    "unknown cve",
			prepare: func(source *fakeSource) { source.vulnerabilities = nil },
		},
		{
			name:      "known but no project affected",
			prepare:   func(source *fakeSource) { source.projects = nil },
			wantKnown: true,
		},
		{
			name: "open finding is affected and not patched",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{finding("vuln-1", "lib", "NOT_SET", false)}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantAffectedList: []string{"alpha@1.0:org/lib@2.0"},
		},
		{
			name: "in triage stays open",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{finding("vuln-1", "lib", "IN_TRIAGE", false)}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantAffectedList: []string{"alpha@1.0:org/lib@2.0"},
		},
		{
			name: "exploitable stays open",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{finding("vuln-1", "lib", "EXPLOITABLE", false)}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantAffectedList: []string{"alpha@1.0:org/lib@2.0"},
		},
		{
			name: "resolved finding is patched",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{finding("vuln-1", "lib", "RESOLVED", false)}
			},
			wantKnown:       true,
			wantAffected:    true,
			wantPatched:     true,
			wantPatchedList: []string{"alpha@1.0:org/lib@2.0"},
		},
		{
			name: "false positive, not affected and suppressed count as handled",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{
					finding("vuln-1", "a", "FALSE_POSITIVE", false),
					finding("vuln-1", "b", "NOT_AFFECTED", false),
					finding("vuln-1", "c", "NOT_SET", true),
				}
			},
			wantKnown:       true,
			wantAffected:    true,
			wantPatched:     true,
			wantPatchedList: []string{"alpha@1.0:org/a@2.0", "alpha@1.0:org/b@2.0", "alpha@1.0:org/c@2.0"},
		},
		{
			name: "mixed findings are affected, not patched, and listed on both sides",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{
					finding("vuln-1", "open", "NOT_SET", false),
					finding("vuln-1", "done", "RESOLVED", false),
				}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantAffectedList: []string{"alpha@1.0:org/open@2.0"},
			wantPatchedList:  []string{"alpha@1.0:org/done@2.0"},
		},
		{
			name: "findings of other vulnerabilities are ignored",
			prepare: func(source *fakeSource) {
				source.findings["proj-a"] = []dtrack.Finding{
					finding("vuln-1", "mine", "RESOLVED", false),
					finding("other", "unrelated", "NOT_SET", false),
				}
			},
			wantKnown:       true,
			wantAffected:    true,
			wantPatched:     true,
			wantPatchedList: []string{"alpha@1.0:org/mine@2.0"},
		},
		{
			name: "affected project without matching finding is treated as open",
			prepare: func(source *fakeSource) {
				source.projects["NVD/CVE-2024-1"][0].AffectedComponentUUIDs = []string{"uuid-9"}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantAffectedList: []string{"alpha@1.0:uuid-9"},
		},
		{
			name: "fix available from a second source",
			prepare: func(source *fakeSource) {
				source.vulnerabilities["GITHUB/CVE-2024-1"] = dtrack.Vulnerability{UUID: "vuln-gh", VulnID: "CVE-2024-1", Source: "GITHUB", PatchedVersions: " 1.2.3 "}
				source.findings["proj-a"] = []dtrack.Finding{finding("vuln-1", "lib", "NOT_SET", false)}
			},
			wantKnown:        true,
			wantAffected:     true,
			wantFix:          true,
			wantAffectedList: []string{"alpha@1.0:org/lib@2.0"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := newFakeSource()
			testCase.prepare(source)
			assessor := NewAssessor(source, []string{"NVD", "GITHUB"})

			result, err := assessor.Assess(context.Background(), "CVE-2024-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.KnownToDependencyTrack != testCase.wantKnown || result.Affected != testCase.wantAffected ||
				result.Patched != testCase.wantPatched || result.FixAvailable != testCase.wantFix {
				t.Fatalf("got %+v", result)
			}
			assertList(t, "affected components", result.AffectedComponents, testCase.wantAffectedList)
			assertList(t, "patched components", result.PatchedComponents, testCase.wantPatchedList)
		})
	}
}

func assertList(t *testing.T, label string, got []string, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
}

func TestAssessPropagatesErrors(t *testing.T) {
	boom := errors.New("boom")
	testCases := []struct {
		name    string
		prepare func(*fakeSource)
	}{
		{name: "vulnerability lookup", prepare: func(source *fakeSource) { source.vulnerabilityError = boom }},
		{name: "project listing", prepare: func(source *fakeSource) { source.projectsError = boom }},
		{name: "finding listing", prepare: func(source *fakeSource) { source.findingsError = boom }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := newFakeSource()
			testCase.prepare(source)
			_, err := NewAssessor(source, []string{"NVD"}).Assess(context.Background(), "CVE-2024-1")
			if !errors.Is(err, boom) {
				t.Fatalf("want wrapped boom, got %v", err)
			}
		})
	}
}

func TestAssessCachesFindingsPerProject(t *testing.T) {
	source := newFakeSource()
	source.vulnerabilities["NVD/CVE-2024-2"] = dtrack.Vulnerability{UUID: "vuln-2", VulnID: "CVE-2024-2", Source: "NVD"}
	source.projects["NVD/CVE-2024-2"] = []dtrack.AffectedProject{{UUID: "proj-a", Name: "alpha", Version: "1.0"}}
	source.findings["proj-a"] = []dtrack.Finding{
		finding("vuln-1", "lib", "RESOLVED", false),
		finding("vuln-2", "lib", "NOT_SET", false),
	}
	assessor := NewAssessor(source, []string{"NVD"})

	first, err := assessor.Assess(context.Background(), "CVE-2024-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := assessor.Assess(context.Background(), "CVE-2024-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source.findingCalls["proj-a"] != 1 {
		t.Fatalf("findings fetched %d times, want 1", source.findingCalls["proj-a"])
	}
	if !first.Patched || second.Patched {
		t.Fatalf("unexpected results: %+v %+v", first, second)
	}
}
