# Local Docker secret files

Create one file per enabled secret before starting Compose. Each file should contain
only the secret value followed by an optional newline, and should be readable only by
the deployment operator. Compose mounts these files at `/run/secrets/*`; no secret
value is placed in an image, normal runtime YAML, or service environment variable.

Required filenames:

- `postgres_password`
- `database_url` (a SQLAlchemy-compatible URL containing the database password)

Future provider credentials must use the same file-backed `/run/secrets` pattern. Use
a customer secret manager or an alternate secret-file directory for production.
