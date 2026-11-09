"""Bounded, observable execution jobs with cooperative cancellation and long polling."""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from time import monotonic, sleep

from .broker_client import call
from .config import Config
from .store import Store


TERMINAL_STATES = frozenset({"completed", "failed", "timed_out", "cancelled", "lost"})


class Jobs:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store
        self.pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="kali-mcp-job")
        self._running: set[str] = set()
        self._lock = Lock()
        self._pending: dict[str, int] = {}
        self._futures: dict[str, Future] = {}
        self._cancel_requested: set[str] = set()
        self.max_pending = 24
        self.max_per_actor = 6

    def _release_actor(self, actor: str) -> None:
        self._pending[actor] = max(0, self._pending.get(actor, 1) - 1)
        if not self._pending[actor]:
            self._pending.pop(actor, None)

    def submit(self, *, actor: str, tool_id: str, mode: str, operation: str, payload: dict) -> dict:
        with self._lock:
            if sum(self._pending.values()) >= self.max_pending:
                raise ValueError("Job queue full")
            if self._pending.get(actor, 0) >= self.max_per_actor:
                raise ValueError("Client job quota exceeded")
            self._pending[actor] = self._pending.get(actor, 0) + 1
            try:
                job_id = self.store.new_job(actor, tool_id, mode, payload)
                self.store.audit(actor, "job.submit", "allow", f"{job_id}:{tool_id}")
                self._futures[job_id] = self.pool.submit(self._worker, job_id, operation, payload, actor)
            except BaseException:
                self._release_actor(actor)
                raise
        return {"ok": True, "job_id": job_id, "state": "queued"}

    def _worker(self, job_id: str, operation: str, payload: dict, actor: str) -> None:
        try:
            with self._lock:
                if job_id in self._cancel_requested:
                    self.store.job_state(job_id, "cancelled",
                                         result={"ok": True, "cancelled": True})
                    return
                self._running.add(job_id)
                self.store.job_state(job_id, "running")
            deadline = max(5, min(self.cfg.max_job_seconds, int(payload.get("timeout", 60))))
            result = call(self.cfg.broker_socket, operation,
                          {**payload, "job_id": job_id}, timeout=deadline + 15)
            exit_code = result.get("exit_code")
            if result.get("cancelled") is True:
                state = "cancelled"
            elif result.get("timed_out") is True:
                state = "timed_out"
            else:
                state = "completed" if exit_code in (None, 0) else "failed"
            self.store.job_state(job_id, state, result=result, exit_code=exit_code)
        except Exception as exc:
            self.store.job_state(job_id, "failed", result={"error": str(exc)})
            self.store.audit("broker", "job.failed", "deny", f"{job_id}: {str(exc)[:300]}")
        finally:
            with self._lock:
                self._running.discard(job_id)
                self._futures.pop(job_id, None)
                self._cancel_requested.discard(job_id)
                self._release_actor(actor)

    def status(self, job_id: str) -> dict:
        result = self.store.get_job(job_id)
        if result is None:
            return {"ok": False, "error": "Unknown job"}
        return {"ok": True, "job": result}

    def wait(self, job_id: str, timeout: int = 15) -> dict:
        """Wait up to 30 seconds for completion instead of high-frequency polling."""
        seconds = max(0, min(30, int(timeout)))
        until = monotonic() + seconds
        while True:
            response = self.status(job_id)
            if not response["ok"] or response["job"]["state"] in TERMINAL_STATES:
                return response
            remaining = until - monotonic()
            if remaining <= 0:
                return {**response, "pending": True, "retry_after_seconds": 2}
            sleep(min(0.25, remaining))

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            job = self.store.get_job(job_id)
            if job is None:
                return {"ok": False, "error": "Unknown job"}
            if job["state"] in TERMINAL_STATES:
                return {"ok": False, "error": "Job already finished"}
            actor = job["actor"]
            future = self._futures.get(job_id)
            if future is not None and future.cancel():
                self.store.job_state(job_id, "cancelled",
                                     result={"ok": True, "cancelled": True, "queued": True})
                self._futures.pop(job_id, None)
                self._release_actor(actor)
                self.store.audit(actor, "job.cancel", "allow", f"{job_id}:queued")
                return {"ok": True, "job_id": job_id, "state": "cancelled"}
            # A running Future may not yet have reached the broker. Both sides
            # check this cancellation request before starting the process.
            self._cancel_requested.add(job_id)
        try:
            call(self.cfg.broker_socket, "job_cancel", {"job_id": job_id}, timeout=8)
        except Exception as exc:
            # Cancellation is best effort; never claim it succeeded if IPC failed.
            self.store.audit(actor, "job.cancel", "failed", f"{job_id}:{type(exc).__name__}")
            return {"ok": False, "error": "Cancellation could not be confirmed by the Agent"}
        self.store.audit(actor, "job.cancel", "allow", f"{job_id}:requested")
        return {"ok": True, "job_id": job_id, "state": "cancellation_requested",
                "message": "Agent accepted cancellation; use jobs_wait to confirm terminal state"}

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=False)
