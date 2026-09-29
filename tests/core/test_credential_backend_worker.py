"""Tests for credential backend helper worker process and bounded execution."""

import pytest

from notebooklm_tools.core.credential_backend_worker import (
    BackendTimeoutError,
    CredentialWorkerClient,
    is_desktop_session,
)
from notebooklm_tools.core.credential_store import (
    InMemoryCredentialBackend,
    RealCredentialStoreAccessAttemptedError,
)


def test_desktop_session_detection():
    """is_desktop_session returns a boolean."""
    assert isinstance(is_desktop_session(), bool)


def test_worker_in_memory_backend():
    """Worker client works with an in-memory backend directly."""
    backend = InMemoryCredentialBackend()
    worker = CredentialWorkerClient(backend=backend)

    assert worker.get_password("test_srv", "acc1") is None
    worker.set_password("test_srv", "acc1", "secret_val")
    assert worker.get_password("test_srv", "acc1") == "secret_val"

    worker.delete_password("test_srv", "acc1")
    assert worker.get_password("test_srv", "acc1") is None


def test_worker_timeout_terminates_and_reaps():
    """Worker terminates helper and raises BackendTimeoutError on timeout."""

    class HangingBackend:
        def get_password(self, service: str, account: str) -> str | None:
            import time

            time.sleep(2)
            return "too_late"

        def set_password(self, service: str, account: str, password: str) -> None:
            import time

            time.sleep(2)

        def delete_password(self, service: str, account: str) -> None:
            import time

            time.sleep(2)

    worker = CredentialWorkerClient(backend=HangingBackend(), timeout_seconds=0.1)
    with pytest.raises(BackendTimeoutError) as exc_info:
        worker.get_password("test_srv", "acc1")

    err = str(exc_info.value)
    assert "timed out" in err.lower()


def test_worker_helper_fails_closed_in_tests():
    """Worker helper process started in tests must fail closed against real store."""
    worker = CredentialWorkerClient(backend=None, use_subprocess=True, timeout_seconds=2.0)
    with pytest.raises((RealCredentialStoreAccessAttemptedError, RuntimeError)):
        worker.get_password("test_srv", "acc1")
