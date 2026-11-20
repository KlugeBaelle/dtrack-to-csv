package report

import (
	"bytes"
	"errors"
	"testing"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/assessment"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

func TestWriteCSV(t *testing.T) {
	results := []assessment.Result{
		{
			CVE:                "CVE-2024-1",
			Affected:           true,
			Patched:            false,
			FixAvailable:       true,
			AffectedComponents: []string{"alpha@1.0:org/lib@2.0", "beta:org/lib@2.0"},
			PatchedComponents:  []string{`gamma:"quoted", name@1`},
			PatchedVersions:    []string{"1.2.3"},
		},
		{CVE: "CVE-2024-2"},
	}
	want := "CVE,affected,patched,fix_available,affected_components,patched_components,patched_versions\n" +
		"CVE-2024-1,yes,no,yes,alpha@1.0:org/lib@2.0;beta:org/lib@2.0,\"gamma:\"\"quoted\"\", name@1\",1.2.3\n" +
		"CVE-2024-2,no,no,no,,,\n"

	var buffer bytes.Buffer
	err := WriteCSV(&buffer, results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buffer.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buffer.String(), want)
	}
}

func TestWriteCSVReportsWriterFailure(t *testing.T) {
	err := WriteCSV(failingWriter{}, []assessment.Result{{CVE: "CVE-2024-1"}})
	if err == nil {
		t.Fatal("expected an error")
	}
}
