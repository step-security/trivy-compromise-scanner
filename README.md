# trivy-compromise-scanner

A CLI tool to audit GitHub Actions workflow run logs for evidence of the **aquasecurity/trivy supply chain compromise** (2026-03-19 to 2026-03-20).

It scans your repositories' workflow run logs within the compromise window, searching for any run that used a compromised action reference or commit SHA.

![Demo](assets/demo.png)

---

## Installation

### Using `go install` (recommended)

```bash
go install github.com/step-security/trivy-compromise-scanner@latest
```

This installs the `trivy-compromise-scanner` binary to your `$GOPATH/bin`.

### Build from source

```bash
git clone https://github.com/step-security/trivy-compromise-scanner
cd trivy-compromise-scanner
go build -o trivy-compromise-scanner .
```

Requires Go 1.25+.

### Using Docker

You can build and run `trivy-compromise-scanner` in a container without installing Go locally.

```bash
docker build -t trivy-compromise-scanner .
```

---

## Usage

```bash
trivy-compromise-scanner [flags]
```

### Flags

| Flag | Short | Env | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` | `-t` | `GITHUB_TOKEN` | — | GitHub PAT (**required**) |
| `--org` | | — | — | Org name(s); repeatable or comma-separated |
| `--repo` | `-r` | — | — | `owner/repo`; repeatable or comma-separated |
| `--since` | | — | `2026-03-19T17:00:00Z` | Compromise window start (RFC3339) |
| `--until` | | — | `2026-03-20T06:00:00Z` | Compromise window end (RFC3339) |
| `--output` | | — | stdout | Output file path |
| `--format` | `-f` | — | `json` | Output format: `json` or `csv` |
| `--workers` | `-w` | — | `5` | Concurrent repo scanners |
| `--dry-run` | | — | false | Validate PAT permissions and exit |
| `--verbose` | `-v` | — | false | Debug logging |

At least one of `--org` or `--repo` is required.

### Required PAT Scopes

- `repo` (or `public_repo` for public repos only) — to list workflow runs and download logs
- `read:org` — required when scanning organizations with `--org`

### Running Using Docker

When using docker the arguments can be passed in after the container name.  Environment variables be loaded via `-e`.  And if you want JSON or CSV output files then mount the target using `-v`.

```bash
docker run --rm \
  -e GITHUB_TOKEN=ghp_yourtokenhere \
  -v "$PWD:/workspace" \
  trivy-compromise-scanner \
  --repo owner/repo \
  --output /workspace/results.json
```

---

## Examples

```bash
# Validate PAT permissions without scanning
trivy-compromise-scanner --token $GITHUB_TOKEN --repo owner/repo --dry-run

# Scan a single repo, output JSON to stdout
trivy-compromise-scanner --token $GITHUB_TOKEN --repo owner/repo

# Scan a single repo, save JSON to file
trivy-compromise-scanner --token $GITHUB_TOKEN --repo owner/repo --output results.json

# Scan multiple repos
trivy-compromise-scanner --token $GITHUB_TOKEN \
  --repo owner/repo1 \
  --repo owner/repo2

# Scan an entire organization, output CSV
trivy-compromise-scanner --token $GITHUB_TOKEN \
  --org myorg \
  --format csv \
  --output results.csv

# Scan with verbose logging and custom time window
trivy-compromise-scanner --token $GITHUB_TOKEN \
  --repo owner/repo \
  --since 2026-03-19T00:00:00Z \
  --until 2026-03-20T23:59:59Z \
  --verbose
```

---

## Output

### Summary Table (always printed to stdout)

```plain
SUMMARY
Scanned at:    2026-03-20T12:00:00Z
Repos scanned: 3
Runs scanned:  42
Findings:      1

FINDINGS
REPO              RUN ID      WORKFLOW        TRIGGERED AT                  MATCHES
myorg/my-service  12345678    CI              2026-03-19 18:31:05 +0000 UTC  aquasecurity/trivy-action@abc1234...
```

### JSON Output

```json
{
  "scanned_at": "2026-03-20T12:00:00Z",
  "total_repos": 3,
  "total_runs_scanned": 42,
  "total_findings": 1,
  "findings": [
    {
      "org": "myorg",
      "repo": "myorg/my-service",
      "workflow_name": "CI",
      "run_id": 12345678,
      "run_url": "https://github.com/myorg/my-service/actions/runs/12345678",
      "triggered_at": "2026-03-19 18:31:05 +0000 UTC",
      "matches": [
        {
          "pattern": "aquasecurity/trivy-action@abc1234...",
          "file": "1_Run trivy-action.txt",
          "snippet": "##[group]Run aquasecurity/trivy-action@abc1234...\n  with:"
        }
      ]
    }
  ]
}
```

### CSV Output

```csv
org,repo,workflow_name,run_id,run_url,triggered_at,matches
myorg,myorg/my-service,CI,12345678,https://github.com/...,2026-03-19 18:31:05 +0000 UTC,aquasecurity/trivy-action@abc1234...
```

---

## Updating Compromised Patterns

The list of compromised action references lives in `internal/scanner/patterns.go`:

```go
var CompromisedActions = map[string][]string{
    // "aquasecurity/trivy-action": {
    //     "abc1234def5678901234567890123456789012345",
    // },
}
```

Add the confirmed compromised action names and their SHA(s) here. Multiple SHAs per action are supported. The tool will compile these into regexes at startup and match them against log text.

---

## How It Works

1. **Enumerate repos** — expands `--org` flags into full repo lists via the GitHub API; merges with explicit `--repo` targets
2. **List workflow runs** — queries each repo for runs within the `--since`/`--until` window
3. **Download logs** — fetches the log zip for each run (handles 404 for purged logs gracefully)
4. **Match patterns** — scans each log file's text for `action@sha` references matching the compromised patterns
5. **Report** — outputs a summary table plus JSON or CSV with full match details including surrounding context

---

## Rate Limiting

The scanner respects GitHub API rate limits:

- Retries once after sleeping until reset on `RateLimitError` or `AbuseRateLimitError`
- Proactively throttles when fewer than 100 API requests remain

Use `--workers` to tune concurrency (default: 5). Lower this value if you encounter rate limit issues.

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success (even if findings were found) |
| `1` | Fatal error (invalid flags, permission failure, API error) |

---

## License

Apache 2.0
