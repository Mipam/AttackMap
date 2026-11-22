# PyInstaller spec for the AttackMap Windows GUI + CLI (onedir, fast build).
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).parent

# Official analyzer plugins collected in full (submodules + data). This list
# must stay in sync with pyproject.toml [project.optional-dependencies] all.
ANALYZER_PKGS = [
    "attackmap_analyzer_php_web",
    "attackmap_analyzer_php_laminas",
    "attackmap_analyzer_omeka_s",
    "attackmap_analyzer_python",
    "attackmap_analyzer_node_service",
    "attackmap_analyzer_iac",
    "attackmap_analyzer_rust",
    "attackmap_analyzer_go",
    "attackmap_analyzer_java_spring",
    "attackmap_analyzer_dotnet",
    "attackmap_analyzer_terraform",
    "attackmap_analyzer_c",
    "attackmap_analyzer_cpp",
    "attackmap_analyzer_swift",
    "attackmap_analyzer_atproto",
]

binaries: list = []
datas: list = [
    (str(ROOT / "src" / "attackmap" / "surfaces" / "ui" / "web"), "attackmap/surfaces/ui/web"),
    (str(ROOT / "src" / "attackmap" / "surfaces" / "ui" / "fixtures"), "attackmap/surfaces/ui/fixtures"),
    (str(ROOT / "src" / "attackmap" / "reasoning" / "taint_sinks.yaml"), "attackmap/reasoning"),
]
hiddenimports: list = [
    "attackmap.surfaces.cli",
    "attackmap.orchestration.analyzers",
    "attackmap.surfaces.ui",
    "attackmap.surfaces.ui.launch",
    "attackmap.surfaces.ui.server",
    "attackmap.surfaces.ui.runner",
    "attackmap.surfaces.ui.config",
    "attackmap.surfaces.ui.report",
    "attackmap.surfaces.ui.output",
    "attackmap.surfaces.ui.secrets",
    "attackmap.surfaces.ui.watch",
    "attackmap.surfaces.ui.suppress_write",
    "attackmap.surfaces.ui.spawn",
    "typer",
    "pydantic",
    "networkx",
    "yaml",
    "webview",
]

for pkg in ANALYZER_PKGS:
    pkg_datas, pkg_binaries, pkg_hiddenimports = collect_all(pkg)
    datas.extend(pkg_datas)
    binaries.extend(pkg_binaries)
    hiddenimports.extend(pkg_hiddenimports)

a = Analysis(
    [str(ROOT / "installer" / "entry.py")],
    pathex=[str(ROOT / "src")],
    optimize=0,
    module_collection_mode=None,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "pytest",
        "IPython",
        "notebook",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="attackmap",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="attackmap",
)
