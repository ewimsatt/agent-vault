# agent-vault Integration Examples

## Claude Desktop (MCP Server)

Add this to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "agent-vault-mcp",
      "args": ["--repo", "/path/to/your/vault-repo", "--key", "/path/to/agent.key"]
    }
  }
}
```

The MCP server holds the agent's private key in memory — the agent process never touches key material. It exposes two tools:

- `agent_vault_get(secret)` — decrypt and return a secret
- `agent_vault_list(group?)` — list available secrets with metadata

## Docker

### Dockerfile

```dockerfile
FROM python:3.12-slim

RUN pip install agent-vault

COPY agent.py /app/agent.py
WORKDIR /app
CMD ["python", "agent.py"]
```

### agent.py

```python
import os
from agent_vault import Vault

vault = Vault(
    repo_path="/vault",
    key_str=os.environ["AGENT_VAULT_KEY"],
    auto_pull=True,
)

api_key = vault.get("stripe/api-key")
# Use the secret...
```

### Run

Mount the vault repo as a read-only volume and inject the agent key via environment variable:

```bash
docker run \
  -v /path/to/vault-repo:/vault:ro \
  -e AGENT_VAULT_KEY="$(cat ~/.agent-vault/agents/my-agent.key)" \
  my-agent-image
```

## GitHub Actions

Store the agent's private key as a GitHub Actions secret named `AGENT_VAULT_KEY`. The CLI and SDK both resolve keys from this environment variable automatically.

```yaml
name: Deploy
on:
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agent-vault
        run: cargo install --path .

      - name: Retrieve secrets
        env:
          AGENT_VAULT_KEY: ${{ secrets.AGENT_VAULT_KEY }}
        run: |
          DB_URL=$(agent-vault get postgres/connection-string)
          echo "::add-mask::$DB_URL"
          echo "DB_URL=$DB_URL" >> "$GITHUB_ENV"

      - name: Deploy
        run: ./deploy.sh
```

The `::add-mask::` directive prevents secret values from appearing in CI logs.

## Python SDK in a FastAPI App

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI

from agent_vault import Vault

vault: Vault

@asynccontextmanager
async def lifespan(app: FastAPI):
    global vault
    vault = Vault(
        repo_path="/path/to/vault",
        key_path="~/.agent-vault/agents/my-agent.key",
    )
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/process-payment")
async def process_payment():
    stripe_key = vault.get("stripe/api-key")
    # Use stripe_key for this request...
    return {"status": "ok"}
```
