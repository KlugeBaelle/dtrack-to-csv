package cveid

import (
	"reflect"
	"strings"
	"testing"
)

func TestCollect(t *testing.T) {
	testCases := []struct {
		name      string
		arguments []string
		list      string
		want      []string
		wantError bool
	}{
		{name: "arguments", arguments: []string{"CVE-2024-3094", "CVE-2023-44487"}, want: []string{"CVE-2024-3094", "CVE-2023-44487"}},
		{name: "lowercase is normalized", arguments: []string{"cve-2024-3094"}, want: []string{"CVE-2024-3094"}},
		{name: "comma separated argument", arguments: []string{"CVE-2024-1111,CVE-2024-2222"}, want: []string{"CVE-2024-1111", "CVE-2024-2222"}},
		{name: "list with comments and blanks", list: "# header\nCVE-2024-1111 # trailing\n\nCVE-2024-2222, CVE-2024-3333\n", want: []string{"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"}},
		{name: "duplicates keep first position", arguments: []string{"CVE-2024-1111", "CVE-2024-2222"}, list: "cve-2024-1111\nCVE-2024-4444", want: []string{"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-4444"}},
		{name: "long sequence number", arguments: []string{"CVE-2024-1234567"}, want: []string{"CVE-2024-1234567"}},
		{name: "nothing given", wantError: true},
		{name: "only comments", list: "# nothing\n", wantError: true},
		{name: "invalid argument", arguments: []string{"CVE-24-1"}, wantError: true},
		{name: "invalid in list", arguments: []string{"CVE-2024-1111"}, list: "GHSA-xxxx-yyyy-zzzz", wantError: true},
		{name: "path traversal attempt", arguments: []string{"CVE-2024-1111/../../x"}, wantError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var got []string
			var err error
			if testCase.list != "" {
				got, err = Collect(testCase.arguments, strings.NewReader(testCase.list))
			} else {
				got, err = Collect(testCase.arguments, nil)
			}
			if testCase.wantError {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("got %v, want %v", got, testCase.want)
			}
		})
	}
}
