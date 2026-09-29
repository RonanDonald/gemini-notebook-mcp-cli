"""Credential backend worker process and bounded execution.

Runs OS credential store operations in a helper process with bounded deadlines
to prevent GUI keychain popups or hung daemons from blocking the CLI or MCP server.
Secrets are passed via private pipes, never argv, env, or temporary files.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, cast

from notebooklm_tools.core.credential_store import (
    MAX_KEYSTORE_ITEM_LENGTH,
    BackendUnavailableError,
    CredentialBackend,
    CredentialStoreError,
    KeystoreItemTooLargeError,
    RealCredentialStoreAccessAttemptedError,
    get_backend,
)

DEFAULT_TIMEOUT_DESKTOP = 60.0
DEFAULT_TIMEOUT_HEADLESS = 10.0


class BackendTimeoutError(CredentialStoreError):
    """Raised when an OS credential store operation times out."""


def is_desktop_session() -> bool:
    """Detect whether the current process is running in a desktop GUI session."""
    if sys.platform == "darwin":
        # macOS has a GUI window server if not running over an SSH session without window server access
        # If SSH_CONNECTION is set and no display session, treat as non-desktop
        return not (os.environ.get("SSH_CONNECTION") and not os.environ.get("DISPLAY"))
    elif sys.platform == "win32":
        # Windows GUI session (SSH key-auth sessions cannot access Credential Manager)
        return not os.environ.get("SSH_CONNECTION")
    else:
        # Linux: check DISPLAY or WAYLAND_DISPLAY
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def get_default_timeout() -> float:
    """Return default timeout based on session type."""
    return DEFAULT_TIMEOUT_DESKTOP if is_desktop_session() else DEFAULT_TIMEOUT_HEADLESS


class CredentialWorkerClient:
    """Client for executing credential store operations with a bounded timeout."""

    def __init__(
        self,
        backend: CredentialBackend | None = None,
        use_subprocess: bool = False,
        timeout_seconds: float | None = None,
    ) -> None:
        self._backend = backend
        self._use_subprocess = use_subprocess
        self._timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else get_default_timeout()
        )

    def get_password(self, service: str, account: str) -> str | None:
        """Retrieve a secret with a bounded deadline."""
        return cast(
            str | None,
            self._execute({"op": "get", "service": service, "account": account}),
        )

    def set_password(self, service: str, account: str, password: str) -> None:
        """Store a secret with a bounded deadline."""
        if len(password) > MAX_KEYSTORE_ITEM_LENGTH:
            raise KeystoreItemTooLargeError(
                f"Password length {len(password)} exceeds maximum allowed {MAX_KEYSTORE_ITEM_LENGTH}"
            )
        self._execute({"op": "set", "service": service, "account": account, "password": password})

    def delete_password(self, service: str, account: str) -> None:
        """Delete a secret with a bounded deadline."""
        self._execute({"op": "delete", "service": service, "account": account})

    def _execute(self, request: dict[str, Any]) -> Any:
        # If an explicit in-memory/in-process backend is provided and subprocess is not requested, execute in-process
        if self._backend is not None and not self._use_subprocess:
            return self._execute_in_process(self._backend, request)

        return self._execute_in_helper(request)

    def _execute_in_process(self, backend: CredentialBackend, request: dict[str, Any]) -> Any:
        import concurrent.futures

        op = request["op"]
        service = request["service"]
        account = request["account"]

        def _run() -> Any:
            if op == "get":
                return backend.get_password(service, account)
            elif op == "set":
                backend.set_password(service, account, request["password"])
                return None
            elif op == "delete":
                backend.delete_password(service, account)
                return None
            raise ValueError(f"Unknown operation: {op}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run)
            try:
                return future.result(timeout=self._timeout_seconds)
            except concurrent.futures.TimeoutError as exc:
                msg = (
                    f"OS credential store operation '{op}' timed out after {self._timeout_seconds}s. "
                    "On macOS, approve the Keychain popup, or run 'nlm auth storage status --verify'."
                    if is_desktop_session()
                    else f"OS credential store operation '{op}' timed out after {self._timeout_seconds}s."
                )
                raise BackendTimeoutError(msg) from exc

    def _execute_in_helper(self, request: dict[str, Any]) -> Any:
        cmd = [
            sys.executable,
            "-m",
            "notebooklm_tools.core.credential_backend_worker",
        ]

        # Preserve test isolation in child processes
        env = os.environ.copy()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        input_data = json.dumps(request) + "\n"
        try:
            stdout_data, stderr_data = proc.communicate(
                input=input_data, timeout=self._timeout_seconds
            )
        except subprocess.TimeoutExpired as exc:
            proc.terminate()
            try:
                proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()

            msg = (
                f"OS credential store operation '{request.get('op')}' timed out after {self._timeout_seconds}s. "
                "On macOS, approve the Keychain popup, or run 'nlm auth storage status --verify'."
                if is_desktop_session()
                else f"OS credential store operation '{request.get('op')}' timed out after {self._timeout_seconds}s."
            )
            raise BackendTimeoutError(msg) from exc

        if proc.returncode != 0:
            err_line = stderr_data.strip() if stderr_data else "Unknown worker failure"
            if "RealCredentialStoreAccessAttemptedError" in err_line:
                raise RealCredentialStoreAccessAttemptedError(err_line)
            if "KeystoreItemTooLargeError" in err_line:
                raise KeystoreItemTooLargeError(err_line)
            raise BackendUnavailableError(
                f"Credential helper failed (code {proc.returncode}): {err_line}"
            )

        try:
            response = json.loads(stdout_data.strip())
        except json.JSONDecodeError as exc:
            raise BackendUnavailableError(
                f"Invalid response from credential helper: {stdout_data!r}"
            ) from exc

        if not response.get("ok"):
            err = response.get("error", "Unknown error")
            err_type = response.get("error_type", "")
            if err_type == "RealCredentialStoreAccessAttemptedError":
                raise RealCredentialStoreAccessAttemptedError(err)
            if err_type == "KeystoreItemTooLargeError":
                raise KeystoreItemTooLargeError(err)
            raise BackendUnavailableError(f"Credential store error: {err}")

        return response.get("result")


def _run_worker_loop() -> int:
    """Worker process main loop: read request JSON from stdin, output response JSON to stdout."""
    try:
        raw_input = sys.stdin.readline()
        if not raw_input:
            return 1
        request = json.loads(raw_input)
        op = request.get("op")
        service = request.get("service")
        account = request.get("account")

        backend = get_backend()
        result = None

        if op == "get":
            result = backend.get_password(service, account)
        elif op == "set":
            password = request.get("password", "")
            backend.set_password(service, account, password)
        elif op == "delete":
            backend.delete_password(service, account)
        else:
            raise ValueError(f"Unknown operation: {op}")

        sys.stdout.write(json.dumps({"ok": True, "result": result}) + "\n")
        sys.stdout.flush()
        return 0
    except RealCredentialStoreAccessAttemptedError as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_type": "RealCredentialStoreAccessAttemptedError",
                }
            )
            + "\n"
        )
        sys.stdout.flush()
        sys.stderr.write(f"RealCredentialStoreAccessAttemptedError: {exc}\n")
        return 2
    except KeystoreItemTooLargeError as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_type": "KeystoreItemTooLargeError",
                }
            )
            + "\n"
        )
        sys.stdout.flush()
        sys.stderr.write(f"KeystoreItemTooLargeError: {exc}\n")
        return 3
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                }
            )
            + "\n"
        )
        sys.stdout.flush()
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(_run_worker_loop())
