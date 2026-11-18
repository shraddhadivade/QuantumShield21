from .auth_routes import router as auth_router
from .crypto_routes import router as crypto_router
from .chat_routes import router as chat_router
from .attack_routes import router as attack_router

__all__ = ["auth_router", "crypto_router", "chat_router", "attack_router"]
