// Package report renders assessment results as CSV.
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/assessment"
)

const listSeparator = ";"

var header = []string{
	"CVE",
	"affected",
	"patched",
	"fix_available",
	"affected_components",
	"patched_components",
	"patched_versions",
}

// WriteCSV writes one row per result, preceded by a header row.
func WriteCSV(writer io.Writer, results []assessment.Result) error {
	csvWriter := csv.NewWriter(writer)
	err := csvWriter.Write(header)
	if err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, result := range results {
		err = csvWriter.Write(row(result))
		if err != nil {
			return fmt.Errorf("write csv row for %s: %w", result.CVE, err)
		}
	}
	csvWriter.Flush()
	err = csvWriter.Error()
	if err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	return nil
}

func row(result assessment.Result) []string {
	return []string{
		result.CVE,
		yesNo(result.Affected),
		yesNo(result.Patched),
		yesNo(result.FixAvailable),
		strings.Join(result.AffectedComponents, listSeparator),
		strings.Join(result.PatchedComponents, listSeparator),
		strings.Join(result.PatchedVersions, listSeparator),
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
