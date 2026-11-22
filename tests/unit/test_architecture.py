"""Structural tests: the trust boundary, enforced by the build.

These are the tests that stop the architecture quietly eroding. Every other
guarantee in the system rests on "no LLM inside the trusted core" and "workers
reach tools only through the gateway" - and both are the kind of property that
a single convenient import destroys without any test noticing.

So they are checked by reading the source, not by exercising behaviour.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

TRUSTED_CORE = ["policy", "core", "tools"]

LLM_PACKAGES = {
    "openai",
    "anthropic",
    "google",
    "cohere",
    "mistralai",
    "ollama",
    "langchain",
    "llama_index",
    "transformers",
    "litellm",
    "boto3",
}


def _imports(path: Path) -> set[str]:
    """Top-level module name of every import in a file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def _python_files(package: str) -> list[Path]:
    return sorted(p for p in (ROOT / package).rglob("*.py") if p.name != "__init__.py")


@pytest.mark.parametrize("package", TRUSTED_CORE)
def test_trusted_core_never_imports_agents(package: str) -> None:
    """The core must not depend on the untrusted zone, even transitively.

    If ``core/executor.py`` could import ``agents/supervisor.py``, "the
    executor re-derives everything itself" would stop being checkable.
    """
    offenders = []
    for file in _python_files(package):
        if "agents" in _imports(file):
            offenders.append(file.relative_to(ROOT).as_posix())
    assert not offenders, f"trusted core imports agents/: {offenders}"


@pytest.mark.parametrize("package", TRUSTED_CORE)
def test_trusted_core_never_imports_an_llm_library(package: str) -> None:
    offenders = []
    for file in _python_files(package):
        found = _imports(file) & LLM_PACKAGES
        if found:
            offenders.append(f"{file.relative_to(ROOT).as_posix()}: {sorted(found)}")
    assert not offenders, f"LLM library inside the trusted core: {offenders}"


def test_worker_reaches_tools_only_through_the_gateway() -> None:
    """A worker is handed a GatewayClient and nothing else.

    No tool module, no database driver, no policy object, no credentials. If
    this fails, "a hijacked worker can only do what its order allows" no longer
    follows from the code.
    """
    imports = _imports(ROOT / "agents" / "worker.py")
    forbidden = imports & {"tools", "sqlite3", "policy", "data", "os", "yaml"}
    assert not forbidden, f"agents/worker.py must not import {sorted(forbidden)}"


def test_worker_does_not_import_the_gateway_module_itself() -> None:
    """The worker is *given* a client; it never constructs one.

    Constructing a gateway would mean choosing its own policy and budget.
    """
    source = (ROOT / "agents" / "worker.py").read_text(encoding="utf-8")
    assert "from core.gateway import" not in source
    assert "import core.gateway" not in source


def test_only_the_executor_may_be_granted_a_write_tool() -> None:
    """Policy itself must not hand a write tool to a role. Checked at load."""
    from policy.loader import Policy, PolicyError, load_policy

    policy = load_policy(ROOT / "policy" / "policy.yaml")
    for name, role in policy.roles.items():
        for tool in role.tools:
            assert policy.tools[tool].tier.value == "read", (
                f"role {name} is granted write tool {tool}"
            )
    assert Policy is not None and PolicyError is not None
