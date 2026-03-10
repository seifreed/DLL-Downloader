"""
Architecture guardrails for layer dependencies.
"""

import ast
import re
import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "dll_downloader"

FORBIDDEN_IMPORTS: dict[str, tuple[str, ...]] = {
    "domain": (
        "application",
        "infrastructure",
        "interfaces",
        "dll_downloader.application",
        "dll_downloader.infrastructure",
        "dll_downloader.interfaces",
    ),
    "application": (
        "infrastructure",
        "interfaces",
        "dll_downloader.infrastructure",
        "dll_downloader.interfaces",
    ),
    "infrastructure": (
        "interfaces",
        "dll_downloader.interfaces",
    ),
}

BOOTSTRAP_FORBIDDEN_IMPORTS = (
    "dll_downloader.infrastructure",
    ".infrastructure",
)
CLI_RUNNER_FORBIDDEN_IMPORTS = (
    "dll_downloader.infrastructure",
    ".infrastructure",
)
INTERFACE_INFRASTRUCTURE_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "interfaces/cli_runner.py": (
        "infrastructure.config.settings",
    ),
}
EXPECTED_PUBLIC_EXPORTS: dict[str, tuple[str, ...]] = {
    "dll_downloader/__init__.py": ("__version__",),
    "dll_downloader/bootstrap.py": (
        "SupportsClose",
        "CloseableHTTPClient",
        "CloseableSecurityScanner",
        "DownloadComponentFactory",
        "DownloadApplicationAssembler",
        "DownloadApplication",
        "build_download_application",
    ),
    "dll_downloader/api.py": (
        "API_VERSION",
        "Architecture",
        "Settings",
        "DownloadDLLRequest",
        "DownloadDLLResponse",
    ),
    "dll_downloader/runtime.py": (
        "Settings",
        "Architecture",
        "load_settings",
        "create_application",
        "create_dependencies",
        "process_downloads",
    ),
    "dll_downloader/interfaces/cli.py": (
        "parse_arguments",
        "set_debug_mode",
        "read_dll_list_from_file",
        "get_architecture",
        "format_response",
        "main",
    ),
    "dll_downloader/interfaces/__init__.py": ("main",),
}
REQUIRED_ARCHITECTURE_DOCS = (
    "ARCHITECTURE.md",
    "docs/GOVERNANCE.md",
    "docs/PUBLIC_API.md",
    "docs/adr/README.md",
)
SUPPORTED_PUBLIC_MODULES = {
    "dll_downloader.api",
    "dll_downloader.runtime",
    "dll_downloader.interfaces.cli",
    "dll_downloader",
}
TEST_INTERNAL_IMPORT_ALLOWLIST = {
    "tests/test_api.py",
    "tests/test_architecture.py",
    "tests/conftest.py",
    "tests/test_bootstrap.py",
    "tests/test_cli_output.py",
    "tests/test_cli_runner.py",
    "tests/test_dll_files_resolver.py",
    "tests/test_download_presenter.py",
    "tests/test_http_client.py",
    "tests/test_settings.py",
    "tests/test_use_cases.py",
    "tests/test_virustotal.py",
    "tests/integration/test_download_flow.py",
    "tests/integration/test_file_repository.py",
}
MODULE_LINE_LIMITS = {
    "dll_downloader/interfaces/cli.py": 280,
    "dll_downloader/interfaces/cli_runner.py": 340,
    "dll_downloader/api.py": 120,
    "dll_downloader/runtime.py": 140,
    "dll_downloader/infrastructure/composition.py": 140,
}
TECHNICAL_ADAPTER_IMPORT_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "dll_downloader/infrastructure/http/http_client.py": (
        "logging",
        "collections.abc",
        "dataclasses",
        "requests",
        "domain.errors",
        "domain.services.http_client",
        "infrastructure.http_session",
        "dll_downloader.domain.errors",
        "dll_downloader.domain.services.http_client",
        "dll_downloader.infrastructure.http_session",
        "http_session",
        "__future__",
    ),
    "dll_downloader/infrastructure/services/virustotal.py": (
        "logging",
        "collections.abc",
        "dataclasses",
        "datetime",
        "requests",
        "domain.entities.dll_file",
        "domain.errors",
        "domain.services",
        "domain.services.security_scanner",
        "infrastructure.http_session",
        "dll_downloader.domain.entities.dll_file",
        "dll_downloader.domain.errors",
        "dll_downloader.domain.services",
        "dll_downloader.domain.services.security_scanner",
        "dll_downloader.infrastructure.http_session",
        "http_session",
        "__future__",
    ),
}


def _unsupported_public_imports(text: str) -> list[str]:
    imported_modules = re.findall(
        r"(?:from|import)\s+(dll_downloader(?:\.[\w_]+)*)",
        text,
    )
    return [
        module_name
        for module_name in imported_modules
        if module_name not in SUPPORTED_PUBLIC_MODULES
    ]


def _imported_modules(file_path: Path) -> list[str]:
    tree = ast.parse(file_path.read_text(), filename=str(file_path))
    imported: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    return imported


def _module_exports(file_path: Path) -> list[str]:
    tree = ast.parse(file_path.read_text(), filename=str(file_path))

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "__all__"
                    and isinstance(node.value, (ast.List, ast.Tuple))
                ):
                    return [
                        elt.value
                        for elt in node.value.elts
                        if isinstance(elt, ast.Constant)
                        and isinstance(elt.value, str)
                    ]

    return []


def _broad_exception_handlers(file_path: Path) -> list[str]:
    tree = ast.parse(file_path.read_text(), filename=str(file_path))
    handlers: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
            continue
        function_name = "<module>"
        for parent in ast.walk(tree):
            if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node in ast.walk(parent):
                function_name = parent.name
                break
        handlers.append(function_name)

    return handlers


def _violations_for_layer(layer_name: str) -> list[str]:
    layer_root = PACKAGE_ROOT / layer_name
    forbidden_prefixes = FORBIDDEN_IMPORTS[layer_name]
    violations: list[str] = []

    for file_path in layer_root.rglob("*.py"):
        for module_name in _imported_modules(file_path):
            if module_name.startswith(forbidden_prefixes):
                violations.append(
                    f"{file_path.relative_to(PROJECT_ROOT)} -> {module_name}"
                )

    return violations


@pytest.mark.unit
@pytest.mark.parametrize("layer_name", ["domain", "application", "infrastructure"])
def test_layers_respect_import_boundaries(layer_name: str) -> None:
    """
    Verify that core layer boundaries are not violated by direct imports.
    """
    assert _violations_for_layer(layer_name) == []


@pytest.mark.unit
def test_bootstrap_stays_free_of_concrete_infrastructure_imports() -> None:
    """
    Verify the bootstrap contracts module does not import concrete adapters.
    """
    bootstrap_file = PACKAGE_ROOT / "bootstrap.py"
    imported_modules = _imported_modules(bootstrap_file)
    assert [
        module_name
        for module_name in imported_modules
        if module_name.startswith(BOOTSTRAP_FORBIDDEN_IMPORTS)
    ] == []


@pytest.mark.unit
def test_public_api_module_stays_free_of_direct_infrastructure_imports() -> None:
    """
    Verify api.py reaches default runtime wiring lazily, not via module-level imports.
    """
    api_file = PACKAGE_ROOT / "api.py"
    imported_modules = _imported_modules(api_file)
    assert [
        module_name
        for module_name in imported_modules
        if module_name.startswith(
            (
                "dll_downloader.infrastructure.composition",
                "dll_downloader.infrastructure.config.loader",
                ".infrastructure.composition",
                ".infrastructure.config.loader",
            )
        )
    ] == []


@pytest.mark.unit
def test_runtime_module_is_the_explicit_default_wiring_surface() -> None:
    """
    Verify runtime.py owns access to default wiring helpers.
    """
    runtime_text = (PACKAGE_ROOT / "runtime.py").read_text()
    assert "infrastructure.config.loader" in runtime_text
    assert "infrastructure.composition" in runtime_text


@pytest.mark.unit
def test_cli_public_api_exposes_entrypoint_not_compat_helpers() -> None:
    """
    Verify CLI compatibility helpers are no longer exported from cli.py.
    """
    exported_names = _module_exports(PACKAGE_ROOT / "interfaces" / "cli.py")
    assert "create_dependencies" not in exported_names
    assert "process_downloads" not in exported_names


@pytest.mark.unit
def test_cli_runner_stays_free_of_concrete_infrastructure_imports() -> None:
    """
    Verify cli_runner depends on injected builders, not production wiring.
    """
    cli_runner_file = PACKAGE_ROOT / "interfaces" / "cli_runner.py"
    imported_modules = _imported_modules(cli_runner_file)
    assert [
        module_name
        for module_name in imported_modules
        if module_name.startswith(CLI_RUNNER_FORBIDDEN_IMPORTS)
    ] == []


@pytest.mark.unit
def test_broad_exception_catch_is_isolated_to_cli_boundary_helper() -> None:
    """
    Verify `except Exception` exists only at the intended outer CLI boundary.
    """
    cli_runner_file = PACKAGE_ROOT / "interfaces" / "cli_runner.py"
    assert _broad_exception_handlers(cli_runner_file) == ["execute_boundary_command"]


@pytest.mark.unit
def test_cli_entrypoint_stays_free_of_direct_infrastructure_imports() -> None:
    """
    Verify cli.py depends on the public API surface instead of concrete wiring.
    """
    cli_file = PACKAGE_ROOT / "interfaces" / "cli.py"
    imported_modules = _imported_modules(cli_file)
    assert [
        module_name
        for module_name in imported_modules
        if module_name.startswith(
            (
                "dll_downloader.infrastructure",
                "..infrastructure",
                ".infrastructure",
            )
        )
    ] == []


@pytest.mark.unit
def test_settings_model_no_longer_exposes_loader_compat_helpers() -> None:
    """
    Verify settings loading lives only in SettingsLoader, not on the model.
    """
    from dll_downloader.infrastructure.config.settings import Settings

    assert not hasattr(Settings, "load")
    assert not hasattr(Settings, "from_env")
    assert not hasattr(Settings, "from_json")
    assert not hasattr(Settings, "_merge")
    assert not hasattr(Settings, "_load_vt_toml_key")


@pytest.mark.unit
def test_http_adapters_no_longer_expose_legacy_session_bridges() -> None:
    """
    Verify infrastructure adapters do not expose _session compatibility shims.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.services.virustotal import VirusTotalScanner

    assert "_session" not in RequestsHTTPClient.__dict__
    assert "_session" not in VirusTotalScanner.__dict__
    assert "_session_headers" not in VirusTotalScanner.__dict__


@pytest.mark.unit
def test_legacy_cli_compat_module_is_removed() -> None:
    """
    Verify compatibility no longer hangs off the CLI adapter package.
    """
    assert not (PACKAGE_ROOT / "interfaces" / "cli_compat.py").exists()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("relative_path", "expected_exports"),
    sorted(EXPECTED_PUBLIC_EXPORTS.items()),
)
def test_public_modules_export_only_the_frozen_surface(
    relative_path: str,
    expected_exports: tuple[str, ...],
) -> None:
    """
    Verify public modules expose only their approved API surface.
    """
    assert _module_exports(PROJECT_ROOT / relative_path) == list(expected_exports)


@pytest.mark.unit
def test_interfaces_import_infrastructure_only_through_allowlisted_modules() -> None:
    """
    Verify interface modules only import infrastructure at explicitly approved points.
    """
    violations: list[str] = []
    interfaces_root = PACKAGE_ROOT / "interfaces"

    for file_path in interfaces_root.rglob("*.py"):
        relative_path = file_path.relative_to(PACKAGE_ROOT).as_posix()
        allowed_imports = INTERFACE_INFRASTRUCTURE_ALLOWLIST.get(relative_path, ())
        for module_name in _imported_modules(file_path):
            if "infrastructure" not in module_name:
                continue
            if module_name not in allowed_imports:
                violations.append(f"{relative_path} -> {module_name}")

    assert violations == []


@pytest.mark.unit
def test_current_architecture_documents_exist() -> None:
    """
    Verify the current architecture source-of-truth documents exist.
    """
    missing = [
        relative_path
        for relative_path in REQUIRED_ARCHITECTURE_DOCS
        if not (PROJECT_ROOT / relative_path).exists()
    ]
    assert missing == []


@pytest.mark.unit
def test_readme_uses_only_supported_public_modules() -> None:
    """
    Verify README examples import only the supported public API surface.
    """
    unsupported = _unsupported_public_imports((PROJECT_ROOT / "README.md").read_text())
    assert unsupported == []


@pytest.mark.unit
def test_docs_examples_use_only_supported_public_modules() -> None:
    """
    Verify docs examples import only the supported public API surface.
    """
    violations: list[str] = []
    for doc_path in sorted((PROJECT_ROOT / "docs").rglob("*.md")):
        for module_name in _unsupported_public_imports(doc_path.read_text()):
            violations.append(
                f"{doc_path.relative_to(PROJECT_ROOT)} -> {module_name}"
            )
    assert violations == []


@pytest.mark.unit
def test_behavior_tests_use_public_api_instead_of_internal_modules() -> None:
    """
    Verify behavior-oriented tests stay on the supported public surface.
    """
    violations: list[str] = []
    tests_root = PROJECT_ROOT / "tests"

    for file_path in tests_root.rglob("test_*.py"):
        relative_path = file_path.relative_to(PROJECT_ROOT).as_posix()
        if relative_path in TEST_INTERNAL_IMPORT_ALLOWLIST:
            continue
        for module_name in _imported_modules(file_path):
            if module_name.startswith(
                (
                    "dll_downloader.infrastructure",
                    "dll_downloader.application.use_cases",
                    "dll_downloader.interfaces.cli_runner",
                    "dll_downloader.interfaces.presenters",
                )
            ):
                violations.append(f"{relative_path} -> {module_name}")

    assert violations == []


@pytest.mark.unit
def test_critical_modules_stay_within_size_limits() -> None:
    """
    Verify critical architectural modules stay below agreed line-count limits.
    """
    violations = [
        f"{relative_path}: {line_count} > {limit}"
        for relative_path, limit in MODULE_LINE_LIMITS.items()
        if (
            line_count := len((PROJECT_ROOT / relative_path).read_text().splitlines())
        ) > limit
    ]
    assert violations == []


@pytest.mark.unit
def test_historical_docs_are_marked_non_current() -> None:
    """
    Verify historical documents clearly announce they are not current design.
    """
    historical_docs = [
        PROJECT_ROOT
        / "docs"
        / "adr"
        / "001-sessionmixin-for-http-session-management.md",
    ]
    violations: list[str] = []

    for doc_path in historical_docs:
        text = doc_path.read_text().lower()
        if "historical" not in text and "superseded" not in text:
            violations.append(doc_path.relative_to(PROJECT_ROOT).as_posix())

    assert violations == []


@pytest.mark.unit
def test_public_api_policy_lists_the_frozen_surface() -> None:
    """
    Verify the public API policy document stays aligned with exported symbols.
    """
    policy_text = (PROJECT_ROOT / "docs" / "PUBLIC_API.md").read_text()
    for symbol in EXPECTED_PUBLIC_EXPORTS["dll_downloader/api.py"]:
        assert f"`{symbol}`" in policy_text
    for symbol in EXPECTED_PUBLIC_EXPORTS["dll_downloader/runtime.py"]:
        assert f"`{symbol}`" in policy_text
    assert "`__version__`" in policy_text


@pytest.mark.unit
def test_technical_adapters_import_only_allowed_dependencies() -> None:
    """
    Verify technical adapters stay on narrow dependency sets.
    """
    violations: list[str] = []

    for relative_path, allowed_prefixes in TECHNICAL_ADAPTER_IMPORT_ALLOWLIST.items():
        file_path = PROJECT_ROOT / relative_path
        for module_name in _imported_modules(file_path):
            if module_name.startswith(allowed_prefixes):
                continue
            violations.append(f"{relative_path} -> {module_name}")

    assert violations == []


@pytest.mark.unit
def test_package_version_matches_project_metadata() -> None:
    """
    Verify the package version stays aligned with pyproject metadata.
    """
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    package_tree = ast.parse((PACKAGE_ROOT / "__init__.py").read_text())
    version_values = [
        node.value.value
        for node in package_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and target.id == "__version__"
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    assert version_values == [pyproject["project"]["version"]]
