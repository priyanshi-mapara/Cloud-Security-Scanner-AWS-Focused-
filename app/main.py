from fastapi import FastAPI

from app.api.routes import router
from app.utils.logging_config import setup_logging

setup_logging()

app = FastAPI(title="cloud-security-scanner", version="1.0.0")
app.include_router(router)
