# dtrack-cve

Reports, for a list of CVEs, whether they affect your Dependency-Track portfolio and whether they are patched. Targets the Dependency-Track v5 REST API (`/api/v1`).

## Setup

```sh
cp .env.example .env     # then fill in DTRACK_URL and DTRACK_API_KEY
go build -o dtrack-cve ./cmd/dtrack-cve
```

The API key needs `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`. Environment variables win over `.env`; `--url` wins over `DTRACK_URL`. `.env` is gitignored.

## Usage

```sh
./dtrack-cve CVE-2024-3094 CVE-2023-44487
./dtrack-cve -f cves.txt -o report.csv      # one or more IDs per line, "#" comments
cat cves.txt | ./dtrack-cve -f -
```

## Output

`CVE,affected,patched,fix_available,affected_components,patched_components,patched_versions`

- **affected**: at least one component in any project is matched to the CVE.
- **patched**: affected, and every matched finding is `RESOLVED`, `FALSE_POSITIVE`, `NOT_AFFECTED` or suppressed. It reflects triage in Dependency-Track, not a version comparison. `no` for CVEs that do not affect you.
- **fix_available**: Dependency-Track knows patched versions for the CVE (`patched_versions`, as reported by GitHub/OSV advisories).
- **affected_components** (still open) and **patched_components** (triaged): `project@version:group/name@version`, separated by `;`.
- CVEs unknown to Dependency-Track are reported as not affected, with a warning on stderr.

## Development

```sh
gofmt -l . && go vet ./... && revive -config revive.toml ./... && go test -race ./...
```
