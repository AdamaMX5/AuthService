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
  - `keys/jwt_private.pem`
  - `keys/jwt_public.pem`

Paths can be overridden with env vars:
- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`

For Linux servers, store keys on the host under `/opt/authservice/keys` and mount them into the container:

```yaml
volumes:
  - /opt/authservice/keys:/app/keys
```


> Real `.pem` key files are gitignored. Only `*.pem.example` templates are committed.

### Private key passphrase
- Set passphrase with env var: `JWT_PRIVATE_KEY_PASSPHRASE`.
- The service uses the passphrase to validate/decode encrypted PEM private keys at signing time.
- Auto-generated key pairs (when files are missing) are created unencrypted by default.
- Store this passphrase in your secret manager (Kubernetes Secret, Vault, Doppler, etc.), **not in Git**.


## Environment variables
Use `.env.example` as template and copy it to `.env`.

About `SECRET_KEY`:
- If you use `ALGORITHM=RS256` (recommended), `SECRET_KEY` is not required and can be removed.
- `SECRET_KEY` is only needed for `HS256` setups.

## Docker
Build image (default base image from Docker Hub):
```bash
# image erstellen und uploaden
docker build -t authservice .
docker push ghcr.io/adamamx5/authservice:latest
# Server
docker pull ghcr.io/adamamx5/authservice:latest
docker run -d -p 8000:8000 ghcr.io/adamamx5/authservice:latest
```

If Docker Hub is blocked/unreliable in your network, override the base image registry:
```bash
docker build -t authservice --build-arg PYTHON_BASE_IMAGE=mcr.microsoft.com/devcontainers/python:1-3.11-bullseye .
```

Run container:
```bash
docker run --rm -p 8000:8000 --env-file .env -v /opt/authservice/keys:/app/keys authservice
```

If you still get `failed to fetch anonymous token` or TLS connection resets, this is usually a network/proxy/firewall issue (not an application code issue). In that case:
- retry on a different network,
- configure Docker proxy settings,
- or use a reachable mirrored/private registry via `PYTHON_BASE_IMAGE`.
