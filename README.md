# Cloud Security Scanner

A production-style AWS security assessment service built for security engineering workflows. It ingests mocked AWS configuration JSON documents, evaluates them against opinionated misconfiguration rules, and exposes findings through both API and CLI interfaces.

## Project overview

`cloud-security-scanner` is designed as a realistic internal security engineering tool:
- modular rule engine for extensible checks
- API-first architecture for CI/CD and platform integrations
- CLI for analyst and developer workflows
- weighted risk scoring for account-level prioritization
- export support (JSON/CSV) for ticketing and governance pipelines

## Architecture

```text
JSON resource files -> File Loader -> Scanner Engine -> Rule Evaluators
                                           |               |
                                           v               v
                                     Findings + Summary  Compliance tags
                                           |
                           +---------------+----------------+
                           |                                |
                        FastAPI                         Typer CLI
```

### Code layout

- `app/main.py`: FastAPI app initialization
- `app/api/`: scan + reporting endpoints
- `app/scanner/`: rule classes and scanner engine
- `app/models/`: Pydantic domain models
- `app/services/`: stateful scan service orchestration
- `app/utils/`: logging, file loading, exports
- `sample_data/`: mocked AWS resource configuration documents
- `tests/`: unit and API tests

## Supported AWS resource types

- S3 buckets
- IAM users
- IAM roles
- IAM policies
- EC2 security groups
- CloudTrail

## Implemented checks (14)

1. S3 bucket is publicly accessible
2. S3 bucket encryption is disabled
3. S3 bucket versioning is disabled
4. S3 bucket access logging disabled
5. IAM policy allows wildcard admin privileges
6. IAM user has old access keys (>90 days)
7. MFA not enabled for IAM users
8. IAM role stale/unused (>180 days)
9. Security group allows `0.0.0.0/0` on SSH (22)
10. Security group allows `0.0.0.0/0` on RDP (3389)
11. Security group allows all ports from internet
12. CloudTrail is disabled
13. CloudTrail is not multi-region
14. CloudTrail log file validation disabled

## Risk scoring model

Each finding contributes weighted risk points:
- `critical`: 10
- `high`: 7
- `medium`: 4
- `low`: 1

Total account/environment risk score is the sum of finding weights.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
make run
```

API served at `http://127.0.0.1:8000`.

## API usage examples

### POST `/scan/file`

```bash
curl -X POST http://127.0.0.1:8000/scan/file \
  -H "Content-Type: application/json" \
  -d '{"path":"sample_data/s3_bucket_public.json"}'
```

### POST `/scan/directory`

```bash
curl -X POST http://127.0.0.1:8000/scan/directory \
  -H "Content-Type: application/json" \
  -d '{"path":"sample_data"}'
```

### GET `/findings`, `/summary`, `/health`

```bash
curl http://127.0.0.1:8000/findings
curl http://127.0.0.1:8000/summary
curl http://127.0.0.1:8000/health
```

## CLI usage examples

```bash
python -m app.cli scan-file sample_data/s3_bucket_public.json
python -m app.cli scan-directory sample_data
python -m app.cli scan-directory sample_data --export-json findings.json --export-csv findings.csv
```

## Sample output

```json
{
  "total_findings": 4,
  "severity_breakdown": {
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "weighted_risk_score": 19
}
```

## Testing and quality

```bash
make lint
make test
```

## Security engineering rationale

- **Rule isolation**: each control is encapsulated in a class for independent validation and easier governance mapping.
- **Parser/evaluator separation**: input loading is isolated from rule execution for cleaner blast-radius control and testability.
- **Actionable findings**: every finding includes remediation guidance and compliance tags to reduce analyst triage time.
- **Weighted scoring**: helps prioritize urgent risks over low-value noise in large cloud estates.
- **Structured logging**: supports integration with SIEM/observability pipelines.

## Future improvements

- Native AWS API ingestion mode (boto3 collectors)
- Multi-account aggregation and tenancy-aware results
- Suppression/exception workflow with expiration
- Historical trend tracking and risk burn-down dashboards
- OPA/Rego policy pack compatibility
- Optional React dashboard for visual triage and filtering
