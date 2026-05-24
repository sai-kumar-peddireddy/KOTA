from __future__ import annotations

import multiprocessing as mp
import os
import time

import uvicorn

from app import create_admin_app, create_ai_app


def run_ai() -> None:
    uvicorn.run(
        create_ai_app(),
        host="0.0.0.0",
        port=int(os.getenv("AI_PORT", "8000")),
        log_level=os.getenv("UVICORN_LOG_LEVEL", "info"),
    )


def run_admin() -> None:
    uvicorn.run(
        create_admin_app(),
        host="0.0.0.0",
        port=int(os.getenv("ADMIN_PORT", "2000")),
        log_level=os.getenv("UVICORN_LOG_LEVEL", "info"),
    )


def run_ai_supervisor():
    while True:
        p = mp.Process(target=run_ai, daemon=False)
        p.start()
        p.join()
        print("[KOTA] AI process exited. Respawning with fresh CUDA context...")
        time.sleep(1)


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    admin = mp.Process(target=run_admin, daemon=True)
    admin.start()          # port 2000 — NEVER restarts, always alive
    run_ai_supervisor()    # port 8000 — restarts on CUDA fault

