# AuthService
A MicroService for Authorisation of User. Can be used in multiple Backend Projects.

## JWT key management

### Endpoints
- `POST /admin/jwt/keys` (ADMIN only): set `private_key`, `public_key`, `algorithm` and optionally `persist_to_files`.
- `GET /jwt/public-key` (public): get current public key + algorithm for JWT verification in other services.
- `GET /admin/jwt/key-storage` (ADMIN only): inspect where key files are stored and whether keys are loaded.

### Where are keys stored?
- In memory after they are configured via endpoint.
- Optionally persisted (default: `persist_to_files=true`) to:
  - `keys/jwt_private.asc`
  - `keys/jwt_public.asc`

Paths can be overridden with env vars:
- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`

> Real `.asc` key files are gitignored. Only `*.asc.example` templates are committed.

### Private key passphrase
- Set passphrase with env var: `JWT_PRIVATE_KEY_PASSPHRASE`.
- The service uses the passphrase to validate/decode encrypted PEM private keys at signing time.
- Store this passphrase in your secret manager (Kubernetes Secret, Vault, Doppler, etc.), **not in Git**.
