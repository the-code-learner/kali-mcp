"""Bounded, observable execution job engine with persistent event history."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import time

from .broker_client import call
from .config import Config
from .store import Store


class Jobs:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store
        self.pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="kali-mcp-job")
        self._running = set()
        self._lock = Lock()

    def submit(self, *, actor: str, tool_id: str, mode: str, operation: str, payload: dict) -> dict:
        job_id = self.store.new_job(actor, tool_id, mode, payload)
        self.store.audit(actor, "job.submit", "allow", f"{job_id}:{tool_id}")
        self.pool.submit(self._worker, job_id, operation, payload)
        return {"ok": True, "job_id": job_id, "state": "queued"}

    def _worker(self, job_id: str, operation: str, payload: dict) -> None:
        with self._lock:
            self._running.add(job_id)
        self.store.job_state(job_id, "running")
        try:
            deadline = max(5, min(self.cfg.max_job_seconds, int(payload.get("timeout", 60))))
            result = call(self.cfg.broker_socket, operation, payload, timeout=deadline + 15)
            exit_code = result.get("exit_code")
            self.store.job_state(job_id, "completed" if exit_code in (None, 0) else "failed",
                                 result=result, exit_code=exit_code)
        except Exception as exc:
            self.store.job_state(job_id, "failed", result={"error": str(exc)})
            self.store.audit("broker", "job.failed", "deny", f"{job_id}: {str(exc)[:300]}")
        finally:
            with self._lock:
                self._running.discard(job_id)

    def status(self, job_id: str) -> dict:
        result = self.store.get_job(job_id)
        if result is None:
            return {"ok": False, "error": "Unknown job"}
        return {"ok": True, "job": result}

    def cancel(self, job_id: str) -> dict:
        # Cancellation requires a cooperative broker process tree protocol,
        # which is not yet implemented. Never report a cancellation as successful.
        job = self.store.get_job(job_id)
        if job is None:
            return {"ok": False, "error": "Unknown job"}
        if job["state"] not in ("queued", "running"):
            return {"ok": False, "error": "Job already finished"}
        return {"ok": False, "error": "Cancellation unavailable in this development build"}

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=False)
