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

# Start the Web UI/API using the documented local Quick Start port.
# The example configuration default is port 8080.
python -m uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 3003

# Optional network-dependent IOC smoke test
python -m src.soc_agent ioc 8.8.8.8
```

Open `http://localhost:3003` for the Web UI or
`http://localhost:3003/api/docs` for Swagger UI.

The command above explicitly selects port `3003` for local Quick Start. The
example configuration default is port `8080`; use whichever port matches your
deployment configuration.

### 6. Configure Claude Desktop (Optional)

Add to Claude Desktop config file:
- **MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cabta": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/absolute/path/to/cabta-llm"
    }
  }
}
```

Run the MCP server as a Python module from the project root and use an
absolute `cwd` path.

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
- Check [Usage Examples](USAGE.md)
- Review [Architecture](ARCHITECTURE.md)

## Getting Help

- Open an issue on GitHub
- Check existing issues for solutions
- Read documentation thoroughly before asking
