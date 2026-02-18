from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from database import get_db
from models import User
import logging
import os
import random
import string

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY")
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY")
JWT_PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.asc")
JWT_PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.asc")
JWT_PRIVATE_KEY_PASSPHRASE = os.getenv("JWT_PRIVATE_KEY_PASSPHRASE")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 14))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


def _read_file_if_exists(path: str | None) -> str | None:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    return file_path.read_text(encoding="utf-8")


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _write_key_file(path: str, key_content: str, *, private: bool) -> None:
    _ensure_parent(path)
    file_path = Path(path)
    file_path.write_text(key_content.strip() + "\n", encoding="utf-8")
    os.chmod(file_path, 0o600 if private else 0o644)


def _load_keys_from_paths() -> None:
    global JWT_PRIVATE_KEY, JWT_PUBLIC_KEY
    if not JWT_PRIVATE_KEY:
        JWT_PRIVATE_KEY = _read_file_if_exists(JWT_PRIVATE_KEY_PATH)
    if not JWT_PUBLIC_KEY:
        JWT_PUBLIC_KEY = _read_file_if_exists(JWT_PUBLIC_KEY_PATH)


def _validate_algorithm(algorithm: str) -> None:
    if not algorithm.startswith("RS") and algorithm != "HS256":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported JWT algorithm '{algorithm}'. Allowed: HS256 or RS*",
        )


def configure_jwt_keys(
    *,
    private_key: str,
    public_key: str,
    algorithm: str = "RS256",
    persist_to_files: bool = True,
) -> None:
    """Configure asymmetric JWT signing keys for access tokens."""
    global JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, ALGORITHM

    _validate_algorithm(algorithm)
    JWT_PRIVATE_KEY = private_key
    JWT_PUBLIC_KEY = public_key
    ALGORITHM = algorithm

    if persist_to_files:
        _write_key_file(JWT_PRIVATE_KEY_PATH, private_key, private=True)
        _write_key_file(JWT_PUBLIC_KEY_PATH, public_key, private=False)


def get_public_jwt_key() -> str | None:
    """Return the currently configured public JWT key."""
    _load_keys_from_paths()
    return JWT_PUBLIC_KEY


def get_jwt_algorithm() -> str:
    """Return configured JWT algorithm."""
    return ALGORITHM


def get_jwt_key_storage_info() -> dict[str, str | bool | None]:
    return {
        "private_key_path": JWT_PRIVATE_KEY_PATH,
        "public_key_path": JWT_PUBLIC_KEY_PATH,
        "private_key_loaded": bool(JWT_PRIVATE_KEY),
        "public_key_loaded": bool(JWT_PUBLIC_KEY),
        "private_key_passphrase_configured": bool(JWT_PRIVATE_KEY_PASSPHRASE),
    }


def _get_signing_key() -> str:
    _load_keys_from_paths()

    if ALGORITHM.startswith("RS"):
        if not JWT_PRIVATE_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT private key is not configured for RS signing",
            )

        # Validate key and optional passphrase early
        serialization.load_pem_private_key(
            JWT_PRIVATE_KEY.encode("utf-8"),
            password=JWT_PRIVATE_KEY_PASSPHRASE.encode("utf-8") if JWT_PRIVATE_KEY_PASSPHRASE else None,
        )
        return JWT_PRIVATE_KEY

    return SECRET_KEY


def _get_verification_key() -> str:
    _load_keys_from_paths()

    if ALGORITHM.startswith("RS"):
        if not JWT_PUBLIC_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT public key is not configured for RS verification",
            )
        serialization.load_pem_public_key(JWT_PUBLIC_KEY.encode("utf-8"))
        return JWT_PUBLIC_KEY

    return SECRET_KEY


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, _get_signing_key(), algorithm=ALGORITHM)
    return encoded_jwt


def verify_jwt(token: str) -> Union[dict, None]:
    if token is None:
        return None
    try:
        payload = jwt.decode(token, _get_verification_key(), algorithms=[ALGORITHM])
        return payload
    except (ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Ungültige JWT-Key Konfiguration: {str(e)}",
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ist abgelaufen",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTClaimsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Ungültige Token-Claims: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Ungültiges Token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    payload = verify_jwt(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="kein Authentifizierungstoken",
            headers={"WWW-Authenticate": "Bearer"}
        )
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ungültige Authentifizierungsdaten (Email ist nicht im Token enthalten)",
            headers={"WWW-Authenticate": "Bearer"}
        )

    logger.info(f"Token: {token}")
    logger.info(f"Email from token: {email}")

    user = await db.scalar(select(User).where(User.email == email))

    logger.info(f"User from DB: {user}")
    logger.info(f"User type: {type(user)}")
    if user:
        logger.info(f"User ID: {user.id if hasattr(user, 'id') else 'No id attribute'}")

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User nicht gefunden",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


def create_token(length: int) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def hash_token(token: str) -> str:
    return sha256(token.encode()).hexdigest()
