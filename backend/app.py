"""
QuantumShield Messenger - FastAPI Main Backend Application.
Serves the Post-Quantum Cryptography REST API and mounts the static Frontend interface.
"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .database import init_db
from .auth import seed_default_users
from .routes.auth_routes import router as auth_router
from .routes.crypto_routes import router as crypto_router
from .routes.chat_routes import router as chat_router
from .routes.attack_routes import router as attack_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and Seed Default Quantum Nodes
    print("[INIT] Initializing SQLite WAL Database...")
    init_db()
    print("[INIT] Seeding Default Quantum Entities (Nova, Orion, Alice, Eve)...")
    seed_default_users()
    print("[READY] QuantumShield Post-Quantum Security System Active.")
    yield


app = FastAPI(
    title="QuantumShield Messenger API",
    description="Post-Quantum End-to-End Encrypted Messaging (ML-KEM-768, HKDF-SHA256, AES-256-GCM, Ed25519)",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth_router)
app.include_router(crypto_router)
app.include_router(chat_router)
app.include_router(attack_router)

# Mount Frontend
frontend_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)

if os.path.exists(frontend_dir):
    app.mount(
        "/",
        StaticFiles(directory=frontend_dir, html=True),
        name="frontend"
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )