# osint-framework

Modular open-source OSINT framework written in Python. Automates passive
reconnaissance from public sources and generates structured reports.

## Features

- DNS enumeration and subdomain discovery
- TLS certificate analysis via CT Logs
- Infrastructure mapping via Shodan, Censys and ipinfo
- Credential leak detection via HaveIBeenPwned
- Social networks and GitHub reconnaissance
- AI-powered analysis via Ollama (local, free): executive summary,
  cross-module correlations and risk scoring
- Report generation in PDF, HTML, JSON and CSV

## Requirements

- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- [Ollama](https://ollama.com/download) (optional, for AI analysis)

## Installation

```bash
git clone https://github.com/0xAudit-Path/osint-framework.git
cd osint-framework
poetry install
```

## Configuration

```bash
cp config.example.yaml config.yaml
# Edit config.yaml and fill in your API keys
```

## Usage

```bash
# Full scan
poetry run osint scan ejemplo.com

# Scan with specific modules
poetry run osint scan ejemplo.com -m dns -m tls

# Interactive AI chat over previous results
poetry run osint chat ejemplo.com --results reports/ejemplo.com.json

# Set up local AI (Ollama)
poetry run osint ai-setup
```

## Modules

| Module | Source | API Key |
|--------|--------|---------|
| DNS | dnspython / aiodns | No |
| TLS | crt.sh / cryptography | No |
| Shodan | Shodan API | Free (academic) |
| Leaks | HaveIBeenPwned | Free |
| WHOIS | python-whois / ipwhois | No |
| Socials | GitHub API | Free |

## License

MIT
