"""
FastAPI Authentication & User Directory Routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ..database import get_user, get_all_users, create_user, log_audit
from ..auth import hash_password, verify_password, ACTIVE_PRIVATE_KEYS
from ..crypto.signatures import Ed25519Manager
from ..crypto.ml_kem import MLKEM768Manager

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "User"


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register_user(req: RegisterRequest):
    if get_user(req.username):
        raise HTTPException(status_code=400, detail="User already registered.")

    ed_pair = Ed25519Manager.generate_keypair()
    kem_pair = MLKEM768Manager.generate_keypair()

    pwd_hash = hash_password(req.password)
    ok = create_user(
        username=req.username,
        password_hash=pwd_hash,
        role=req.role,
        ed25519_hex=ed_pair.public_hex,
        mlkem_hex=kem_pair.public_key_hex
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Database registration failed.")

    ACTIVE_PRIVATE_KEYS[req.username] = {
        "ed25519_priv": ed_pair.private_key,
        "mlkem_dk": kem_pair.private_key
    }

    log_audit("USER_REGISTER", "INFO", f"Registered new quantum entity '{req.username}'.")
    return {
        "status": "success",
        "username": req.username,
        "ed25519_pubkey": ed_pair.public_hex,
        "mlkem_ek": kem_pair.public_key_hex
    }


@router.post("/login")
def login_user(req: LoginRequest):
    user = get_user(req.username)
    if not user or not verify_password(user["password_hash"], req.password):
        log_audit("AUTH_FAILURE", "WARNING", f"Failed authentication attempt for '{req.username}'.")
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    log_audit("AUTH_SUCCESS", "INFO", f"Entity '{req.username}' authenticated.")
    return {
        "status": "success",
        "username": user["username"],
        "role": user["role"],
        "ed25519_pubkey": user["ed25519_pubkey_hex"],
        "mlkem_ek": user["mlkem_ek_hex"]
    }


@router.get("/users")
def list_users():
    return {"users": get_all_users()}


@router.get("/profile/{username}")
def get_profile(username: str):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "username": user["username"],
        "role": user["role"],
        "ed25519_pubkey": user["ed25519_pubkey_hex"],
        "mlkem_ek": user["mlkem_ek_hex"],
        "created_at": user["created_at"]
    }
