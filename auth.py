import os

import jwt
from dotenv import load_dotenv

load_dotenv(override=True)


JWT_SECRET: str = os.getenv("JWT_SECRET")  # type: ignore


def create_token(data: dict[str, str]) -> str:
    return jwt.encode(data, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict[str, str]:
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def verify_admin(authorization: str) -> bool:
    profile = get_profile(authorization)
    access_role = profile.get("role", "").upper()
    if access_role != "ADMIN":
        return False
    return True


def get_profile(authorization: str) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        return {}
    access_token = authorization.split(" ")[1]
    return decode_token(access_token)
