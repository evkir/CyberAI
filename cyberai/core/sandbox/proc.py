"""
Sealed subprocess execution.

Threat model: CyberAI runs analysis tooling (forge, slither, aderyn, halmos,
anvil) over target-controlled source trees. Build systems execute code from the
target by design — foundry.toml, solc plugins, build scripts. That is a code
execution primitive available to the target BEFORE any LLM token is produced.

If the child process inherits os.environ, the target reads our LLM API keys.

run_sealed() never inherits the parent environment. It constructs a minimal
env from a fixed base plus an explicit per-call allowlist, and refuses to pass
anything whose name looks like a credential.

This does not sandbox the filesystem or the network. It closes exactly one
door: environment-borne secret exfiltration. Containerisation covers the rest.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import IO, Any, Mapping, Optional, Sequence

# Variables the child always gets. Nothing here is sensitive.
_BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TERM", "TZ")

_FALLBACK_PATH = "/usr/local/bin:/usr/bin:/bin"

# Defence in depth: even if an allowlist entry is wrong, these never pass.
_SECRET_PATTERN = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWD|PASSWORD|CREDENTIAL|AUTH|SESSION|COOKIE|"
    r"PRIVATE|MNEMONIC|SEED)",
    re.IGNORECASE,
)


class SealedEnvError(RuntimeError):
    """Raised when a caller tries to leak a credential-looking variable."""


def sealed_env(
    allow: Optional[Sequence[str]] = None,
    extra: Optional[Mapping[str, str]] = None,
    home: Optional[Path] = None,
) -> dict[str, str]:
    """Build a minimal environment for an untrusted child process.

    allow: names copied from os.environ if present (e.g. "SSL_CERT_FILE").
    extra: literal key/value pairs set by us (e.g. tool feature flags).
    home:  HOME for the child. Defaults to its cwd-agnostic temp home.
    """
    env: dict[str, str] = {}

    for key in _BASE_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value
    env.setdefault("PATH", _FALLBACK_PATH)

    for key in allow or ():
        if _SECRET_PATTERN.search(key):
            raise SealedEnvError(f"refusing to forward credential-shaped variable: {key}")
        value = os.environ.get(key)
        if value is not None:
            env[key] = value

    for key, value in (extra or {}).items():
        if _SECRET_PATTERN.search(key):
            raise SealedEnvError(f"refusing to inject credential-shaped variable: {key}")
        env[key] = str(value)

    env["HOME"] = str(home) if home else "/tmp/cyberai-worker-home"
    return env


def run_sealed(
    argv: Sequence[str],
    *,
    cwd: Optional[Path | str] = None,
    timeout: Optional[float] = None,
    allow: Optional[Sequence[str]] = None,
    extra_env: Optional[Mapping[str, str]] = None,
    home: Optional[Path] = None,
    check: bool = False,
    stdin: int | IO[Any] | None = None,
) -> subprocess.CompletedProcess[str]:
    """subprocess.run() with a sealed environment. argv only, never a shell.

    stdin: pass subprocess.DEVNULL for tools that would otherwise read the
    operator's terminal. Not a security control — a child can still open
    /dev/tty directly — but it keeps interactive tools from stalling.
    """
    if isinstance(argv, (str, bytes)):
        raise SealedEnvError("argv must be a sequence, not a string")

    env = sealed_env(allow=allow, extra=extra_env, home=home)
    return subprocess.run(  # noqa: S603 — argv list, no shell, sealed env
        list(argv),
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
        stdin=stdin,
    )


def operator_home() -> Path:
    """HOME for tools that need the operator's real toolchain caches.

    forge/anvil read ~/.foundry and ~/.svm; slither reads ~/.solc-select.
    Passing a synthetic HOME breaks them without buying isolation: run_sealed
    does not confine the filesystem, so a child can still reach any absolute
    path. HOME is a functional variable here, not a security control. Real
    filesystem confinement is the container's job.
    """
    return Path.home()


def popen_sealed(
    argv: Sequence[str],
    *,
    cwd: Optional[Path | str] = None,
    stdout: int | IO[Any] | None = None,
    stderr: int | IO[Any] | None = None,
    allow: Optional[Sequence[str]] = None,
    extra_env: Optional[Mapping[str, str]] = None,
    home: Optional[Path] = None,
) -> subprocess.Popen[str]:
    """subprocess.Popen() with a sealed environment, for long-lived children.

    Used for managed daemons (anvil) where run_sealed's capture-and-wait model
    does not apply. Same guarantee: the child never inherits os.environ.
    """
    if isinstance(argv, (str, bytes)):
        raise SealedEnvError("argv must be a sequence, not a string")

    env = sealed_env(allow=allow, extra=extra_env, home=home)
    return subprocess.Popen(  # noqa: S603 — argv list, no shell, sealed env
        list(argv),
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
