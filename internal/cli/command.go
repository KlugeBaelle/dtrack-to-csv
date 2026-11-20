// Package cli wires the Cobra command line to the Dependency-Track client.
package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/assessment"
	"github.com/KlugeBaelle/dtrack-to-csv/internal/config"
	"github.com/KlugeBaelle/dtrack-to-csv/internal/cveid"
	"github.com/KlugeBaelle/dtrack-to-csv/internal/dtrack"
	"github.com/KlugeBaelle/dtrack-to-csv/internal/report"
)

const standardStream = "-"

type options struct {
	envFile    string
	url        string
	inputFile  string
	outputFile string
	sources    []string
	timeout    time.Duration
	verbose    bool
}

// NewRootCommand builds the dtrack-cve command.
func NewRootCommand() *cobra.Command {
	commandOptions := &options{}
	command := &cobra.Command{
		Use:   "dtrack-cve [CVE...]",
		Short: "Report whether CVEs affect and are patched in Dependency-Track",
		Long: `Looks up each CVE in Dependency-Track and writes a CSV with the columns
CVE, affected, patched, fix_available, affected_components,
patched_components and patched_versions.

A CVE is affected when at least one component is matched to it. It is patched
when it is affected and every matched finding is triaged as RESOLVED,
FALSE_POSITIVE, NOT_AFFECTED or suppressed. fix_available is yes when
Dependency-Track knows patched versions for the CVE.

Connection settings come from DTRACK_URL and DTRACK_API_KEY, taken from the
environment first and from the env file (default .env) second.`,
		Example: `  dtrack-cve CVE-2024-3094 CVE-2023-44487
  dtrack-cve -f cves.txt -o report.csv
  cat cves.txt | dtrack-cve -f -`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, arguments []string) error {
			return commandOptions.run(command, arguments)
		},
	}

	flags := command.Flags()
	flags.StringVar(&commandOptions.envFile, "env-file", ".env", "env file with DTRACK_URL and DTRACK_API_KEY")
	flags.StringVar(&commandOptions.url, "url", "", "Dependency-Track base URL (overrides DTRACK_URL)")
	flags.StringVarP(&commandOptions.inputFile, "file", "f", "", `file with CVE IDs, one or more per line ("-" for stdin)`)
	flags.StringVarP(&commandOptions.outputFile, "output", "o", "", "CSV output file (default stdout)")
	flags.StringSliceVar(&commandOptions.sources, "sources", []string{"NVD", "GITHUB", "OSV"}, "Dependency-Track vulnerability sources to search")
	flags.DurationVar(&commandOptions.timeout, "timeout", 5*time.Minute, "overall time limit for the run")
	flags.BoolVarP(&commandOptions.verbose, "verbose", "v", false, "log progress")
	return command
}

func (commandOptions *options) run(command *cobra.Command, arguments []string) error {
	logger := logrus.New()
	logger.SetOutput(command.ErrOrStderr())
	if commandOptions.verbose {
		logger.SetLevel(logrus.DebugLevel)
	}

	identifiers, err := commandOptions.readIdentifiers(command, arguments)
	if err != nil {
		return err
	}
	envFileRequired := command.Flags().Changed("env-file")
	settings, err := config.Load(commandOptions.envFile, envFileRequired, commandOptions.url)
	if err != nil {
		return err
	}
	client, err := dtrack.NewClient(settings.URL, settings.APIKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, commandOptions.timeout)
	defer cancel()

	results, err := assessAll(ctx, logger, assessment.NewAssessor(client, commandOptions.sources), identifiers)
	if err != nil {
		return err
	}
	return commandOptions.writeReport(command, results)
}

func (commandOptions *options) readIdentifiers(command *cobra.Command, arguments []string) ([]string, error) {
	if commandOptions.inputFile == "" {
		return cveid.Collect(arguments, nil)
	}
	if commandOptions.inputFile == standardStream {
		return cveid.Collect(arguments, command.InOrStdin())
	}
	file, err := os.Open(commandOptions.inputFile)
	if err != nil {
		return nil, fmt.Errorf("open CVE list: %w", err)
	}
	defer file.Close()
	return cveid.Collect(arguments, file)
}

func assessAll(ctx context.Context, logger *logrus.Logger, assessor *assessment.Assessor, identifiers []string) ([]assessment.Result, error) {
	results := make([]assessment.Result, 0, len(identifiers))
	for _, identifier := range identifiers {
		logger.Debugf("assessing %s", identifier)
		result, err := assessor.Assess(ctx, identifier)
		if err != nil {
			return nil, err
		}
		if !result.KnownToDependencyTrack {
			logger.Warnf("%s is unknown to Dependency-Track, reporting it as not affected", identifier)
		}
		results = append(results, result)
	}
	return results, nil
}

func (commandOptions *options) writeReport(command *cobra.Command, results []assessment.Result) error {
	var buffer bytes.Buffer
	err := report.WriteCSV(&buffer, results)
	if err != nil {
		return err
	}
	if commandOptions.outputFile == "" || commandOptions.outputFile == standardStream {
		return copyTo(command.OutOrStdout(), &buffer)
	}
	err = os.WriteFile(commandOptions.outputFile, buffer.Bytes(), 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", commandOptions.outputFile, err)
	}
	return nil
}

func copyTo(destination io.Writer, source io.Reader) error {
	_, err := io.Copy(destination, source)
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
