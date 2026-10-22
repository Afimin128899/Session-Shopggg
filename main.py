from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Session-Shopggg", version="1.0.0")


@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "Session-Shopggg",
        "message": "Deployment health check. The Telegram bot itself runs in app.py and should be hosted on a long-lived worker, not on Vercel serverless.",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
