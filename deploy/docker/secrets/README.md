# Local Docker secret files

Create one file per enabled secret before starting Compose. Each file should contain
only the secret value followed by an optional newline, and should be readable only by
the deployment operator. Compose mounts these files at `/run/secrets/*`; no secret
value is placed in an image, normal runtime YAML, or service environment variable.

Required filenames:

- `postgres_password`
- `database_url` (a SQLAlchemy-compatible URL containing the database password)
- `splunk_token` (the least-privilege token used by API/worker for the approved Splunk endpoint)
- `model_api_key` (the API key for the configured OpenAI-compatible model provider)

The default Compose profile requires the four files above. The optional `mcp` profile additionally requires `mcp_service_subject`, `mcp_tls_ca`, `mcp_tls_client_cert`, and `mcp_tls_client_key`; do not enable that profile until the MCP image module and TLS credentials are qualified.

Future provider credentials must use the same file-backed `/run/secrets` pattern. Use
a customer secret manager or an alternate secret-file directory for production.
