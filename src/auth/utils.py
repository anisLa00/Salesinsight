"""Password hashing, JWT creation/decoding, and URL-safe email tokens."""

import logging
import uuid
from datetime import datetime, timedelta

import jwt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from passlib.context import CryptContext

from src.config import Config

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_EXPIRY = 3600  # seconds


def generate_passwd_hash(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_context.verify(password, password_hash)


def create_access_token(
    user_data: dict, expiry: timedelta | None = None, refresh: bool = False
) -> str:
    payload = {
        "user": user_data,
        "exp": datetime.now()
        + (expiry if expiry is not None else timedelta(seconds=ACCESS_TOKEN_EXPIRY)),
        "jti": str(uuid.uuid4()),
        "refresh": refresh,
    }
    return jwt.encode(
        payload=payload, key=Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM
    )


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            jwt=token, key=Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM]
        )
    except jwt.PyJWTError as exc:
        logging.exception(exc)
        return None


email_verification_serializer = URLSafeTimedSerializer(
    secret_key=Config.JWT_SECRET,
    salt="email-verification",
)

password_reset_serializer = URLSafeTimedSerializer(
    secret_key=Config.JWT_SECRET,
    salt="password-reset",
)


def create_email_verification_token(data: dict) -> str:
    return email_verification_serializer.dumps(data)


def decode_email_verification_token(
    token: str,
    max_age: int = 3600,
) -> dict | None:
    try:
        return email_verification_serializer.loads(token, max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None


def create_password_reset_token(data: dict) -> str:
    return password_reset_serializer.dumps(data)


def decode_password_reset_token(
    token: str,
    max_age: int = 3600,
) -> dict | None:
    try:
        return password_reset_serializer.loads(token, max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None
