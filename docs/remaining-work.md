# Remaining Work

The production vertical slice and Daybreak security hardening are implemented. The following environment and release tasks remain:

1. Start Docker Desktop's Linux engine and enable WSL integration.
2. Configure protected PostgreSQL, database URL, Splunk token, and OpenAI API-key secret files.
3. Configure the production Splunk URL, TLS/CA trust, indexes, and synthetic test data.
4. Install an application-owned non-production known-answer fixture workflow adapter, then run the full Docker Compose stack, migrations, and live Splunk/OpenAI qualification workflow.
5. Implement and qualify MCP tool handlers before enabling the optional `mcp` Compose profile; its current entrypoint fails closed by design.
6. Independently verify external-model approval references against the production GRC or approval system.
7. Pin production container base images by digest and generate reviewed, hash-locked Python dependencies.
8. Configure HTTPS before exposing the interactive application beyond loopback.
9. Address the upstream Starlette `httpx2` migration warning during routine dependency maintenance.

Current verification baseline: 198 Python tests passed; 12 frontend tests passed; TypeScript typecheck and production build passed. Live provider qualification remains blocked until the dedicated fixture adapter is configured.
