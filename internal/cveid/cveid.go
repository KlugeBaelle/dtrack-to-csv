// Package cveid collects and validates CVE identifiers from user input.
package cveid

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Collect merges identifiers from arguments and an optional reader, normalizes
// them to upper case, drops duplicates and keeps the first-seen order.
// The reader holds whitespace or comma separated IDs; "#" starts a comment.
func Collect(arguments []string, reader io.Reader) ([]string, error) {
	var tokens []string
	for _, argument := range arguments {
		tokens = append(tokens, splitTokens(argument)...)
	}
	if reader != nil {
		listedTokens, err := readTokens(reader)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, listedTokens...)
	}

	seen := make(map[string]bool)
	var identifiers []string
	for _, token := range tokens {
		identifier := strings.ToUpper(token)
		if !cvePattern.MatchString(identifier) {
			return nil, fmt.Errorf("%q is not a valid CVE identifier (expected CVE-YYYY-NNNN)", token)
		}
		if seen[identifier] {
			continue
		}
		seen[identifier] = true
		identifiers = append(identifiers, identifier)
	}
	if len(identifiers) == 0 {
		return nil, errors.New("no CVE identifiers given")
	}
	return identifiers, nil
}

func readTokens(reader io.Reader) ([]string, error) {
	var tokens []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		commentStart := strings.Index(line, "#")
		if commentStart >= 0 {
			line = line[:commentStart]
		}
		tokens = append(tokens, splitTokens(line)...)
	}
	err := scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("read CVE list: %w", err)
	}
	return tokens, nil
}

func splitTokens(text string) []string {
	return strings.FieldsFunc(text, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
}
