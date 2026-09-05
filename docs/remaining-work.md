# Remaining Work

The production vertical slice and Daybreak security hardening are implemented. The following environment and release tasks remain:

1. Start Docker Desktop's Linux engine and enable WSL integration.
2. Configure protected PostgreSQL, database URL, Splunk token, and OpenAI API-key secret files.
3. Configure the production Splunk URL, TLS/CA trust, indexes, and synthetic test data.
4. Run the full Docker Compose stack, migrations, and live Splunk/OpenAI qualification workflow.
5. Independently verify external-model approval references against the production GRC or approval system.
6. Pin production container base images by digest and generate reviewed, hash-locked Python dependencies.
7. Configure HTTPS before exposing the interactive application beyond loopback.
8. Address the upstream Starlette `httpx2` migration warning during routine dependency maintenance.

Current verification baseline: 183 Python tests passed; 12 frontend tests passed; TypeScript typecheck and production build passed; Python and npm dependency audits reported no known vulnerabilities.
