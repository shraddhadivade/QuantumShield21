"""
FastAPI Chat & Message History Routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List

from ..database import save_message, get_messages, get_recent_audit_logs, log_audit

router = APIRouter(prefix="/api/chat", tags=["Chat & Messages"])


class SendMessageRequest(BaseModel):
    sender: str
    receiver: str
    kem_ciphertext_hex: str
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str
    signature_hex: str
    is_tampered: bool = False


@router.post("/send")
def send_message(req: SendMessageRequest):
    msg_id = save_message(
        sender=req.sender,
        receiver=req.receiver,
        kem_ciphertext_hex=req.kem_ciphertext_hex,
        nonce_hex=req.nonce_hex,
        ciphertext_hex=req.ciphertext_hex,
        tag_hex=req.tag_hex,
        signature_hex=req.signature_hex,
        is_tampered=req.is_tampered
    )

    log_audit("MESSAGE_STORED", "INFO", f"Message #{msg_id} saved from {req.sender} -> {req.receiver}.")
    return {"status": "success", "message_id": msg_id}


@router.get("/history/{user1}/{user2}")
def get_history(user1: str, user2: str):
    msgs = get_messages(user1, user2)
    return {"messages": msgs}


@router.get("/audit-logs")
def get_audit_logs(limit: int = 50):
    logs = get_recent_audit_logs(limit)
    return {"audit_logs": logs}
