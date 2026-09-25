# Installation Guide

## Prerequisites

- Python 3.10 or higher
- pip package manager
- API keys are optional; empty values disable the corresponding integrations

## Step-by-Step Installation

### 1. Clone Repository

```bash
git clone https://github.com/kanokrot/cabta-llm.git
cd cabta-llm
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv .venv

# Activate on Linux/Mac
source .venv/bin/activate

# Activate on Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Activate on Windows Command Prompt
.venv\Scripts\activate.bat
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure API Keys

```bash
# Copy the canonical configuration template
cp config.yaml.example config.yaml

# Windows PowerShell
Copy-Item config.yaml.example config.yaml

# Edit with your favorite editor
nano config.yaml  # or vim, code, etc.
```

Configure only the integrations required for your workflow. The application
can start with empty API-key values and will disable integrations that are not
configured. Keep populated credentials out of version control.

The loader also accepts an alternate configuration path through the
`BTA_CONFIG` environment variable.

### 5. Test Installation

```bash
# Test CLI entry point
python -m src.soc_agent --help

# Start the Web UI/API using the default web.port from config.yaml.example.
# The configuration default is port 8080.
python -m uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 8080

# Optional network-dependent IOC smoke test
python -m src.soc_agent ioc 8.8.8.8
```

Open `http://localhost:8080` for the Web UI or
`http://localhost:8080/api/docs` for Swagger UI.

Port `3003` is an explicit local-development override used by the repository's
Quick Start documentation and by the current Gmail OAuth callback URI. If you
need that setup, run the same command with `--port 3003` and register/use
`http://localhost:3003/api/settings/gmail/callback` for Gmail OAuth. Otherwise,
use the default `8080` shown above.

### 6. Configure MCP servers (Optional)

The current Web UI/Agent runtime loads MCP server definitions from the
`mcp_servers` list in `config.yaml`. Start from `config.yaml.example` and keep
only the servers available in the local environment. The current structure is:

```yaml
mcp_servers:
  - name: "osint_tools"
    command: "python"
    args: ["-m", "src.mcp_servers.osint_tools"]
    transport: "stdio"
    description: ""
    env: null
    url: null
  - name: "free_osint_tools"
    command: "python"
    args: ["-m", "src.mcp_servers.free_osint_tools"]
    transport: "stdio"
    description: ""
    env: null
    url: null
```

The template also includes the configured `network_tools`,
`malwoverview_tools`, `forensics_tools`, `remnux_tools`, `threat_intel_tools`,
and `remote_tools` servers. Some servers require external tools, services, or
credentials. MCP connections are discovered and managed by CABTA from this
configuration; do not use the legacy `src.server` entry for the current setup.

## Troubleshooting

### Issue: Import errors
**Solution**: Make sure you're in the virtual environment and all dependencies are installed:
```bash
python -m pip install -r requirements.txt
```

### Issue: API errors
**Solution**: Check `config.yaml`. Missing API keys disable the affected
integration; verify credentials only for the services you intend to use.

## Next Steps

- Read the [Configuration section](../README.md#6-configuration)
- Check the [User Manual](USER_MANUAL.md)
- Review [Architecture](ARCHITECTURE.md)

## Getting Help

- Open an issue on GitHub
- Check existing issues for solutions
- Read documentation thoroughly before asking
