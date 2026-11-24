"""AR065 / AC-307: the GUI frontend is plain ES modules with no build step.

Static guards on ``src/attackmap/surfaces/ui/web``:

  * ``index.html`` loads exactly one ``<script type="module">`` entry;
  * every module's relative imports resolve to files that exist on disk;
  * no bundler config or ``package.json`` exists in the web tree;
  * the monolithic ``app.js`` is gone;
  * ``api-types.js`` parses as valid JS and matches ``tools/gen_api_types.py``
    output (the Pydantic schemas in ``api/schemas.py`` stay the source of
    truth);
  * when Node.js is available, every shipped module also passes a real ESM
    syntax parse via ``vm.SourceTextModule`` (no execution).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = REPO_ROOT / "src" / "attackmap" / "surfaces" / "ui" / "web"
SRC_DIR = WEB_ROOT / "src"

IMPORT_RE = re.compile(r"""import\s+(?:[^'"]*?\s+from\s+)?["'](\.[^"']+)["']""")
SCRIPT_RE = re.compile(r"<script\b[^>]*>")

EXPECTED_MODULES = {
    "main.js",
    "api.js",
    "api-types.js",
    "state.js",
    "paint.js",
    "util.js",
    "activity.js",
    "markdown.js",
    "mermaid-lite.js",
}
EXPECTED_VIEWS = {
    "index.js",
    "overview.js",
    "findings.js",
    "exploitability.js",
    "paths.js",
    "surface.js",
    "deps.js",
    "fleet.js",
    "settings.js",
    "review.js",
    "inventory.js",
    "recents.js",
    "diagrams.js",
}
BUNDLER_CONFIG_NAMES = {
    "package.json",
    "package-lock.json",
    "vite.config.js",
    "webpack.config.js",
    "rollup.config.js",
    "esbuild.config.js",
    "parcel.config.js",
    "tsconfig.json",
    "babel.config.js",
    ".babelrc",
}


def _module_files() -> list[Path]:
    return sorted(SRC_DIR.rglob("*.js"))


def test_expected_module_layout() -> None:
    top = {p.name for p in SRC_DIR.glob("*.js")}
    views = {p.name for p in (SRC_DIR / "views").glob("*.js")}
    assert top >= EXPECTED_MODULES, f"missing top-level modules: {EXPECTED_MODULES - top}"
    assert views >= EXPECTED_VIEWS, f"missing view modules: {EXPECTED_VIEWS - views}"
    assert not top & EXPECTED_VIEWS


def test_monolithic_app_js_is_gone() -> None:
    assert not (SRC_DIR / "app.js").exists()
    for html in WEB_ROOT.rglob("*.html"):
        assert "app.js" not in html.read_text(encoding="utf-8"), (
            f"{html.name} still references the monolith"
        )


def test_index_html_loads_module_entry() -> None:
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    scripts = SCRIPT_RE.findall(html)
    module_scripts = [s for s in scripts if 'type="module"' in s]
    assert len(scripts) == 1, f"expected exactly one <script>, found: {scripts}"
    assert len(module_scripts) == 1
    assert 'src="/src/main.js"' in module_scripts[0]


def test_no_bundler_config_in_web_tree() -> None:
    offenders = [
        p.relative_to(WEB_ROOT)
        for p in WEB_ROOT.rglob("*")
        if p.is_file() and p.name in BUNDLER_CONFIG_NAMES
    ]
    assert not offenders, f"bundler config present: {offenders}"


def test_relative_imports_resolve() -> None:
    for module in _module_files():
        text = module.read_text(encoding="utf-8")
        for rel in IMPORT_RE.findall(text):
            target = (module.parent / rel).resolve()
            assert target.is_file(), f"{module.name} imports missing {rel}"


def test_api_types_js_is_current() -> None:
    result = subprocess.run(
        [
            str(REPO_ROOT / ".venv" / "Scripts" / "python.exe"),
            str(REPO_ROOT / "tools" / "gen_api_types.py"),
            "--check",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    text = (SRC_DIR / "api-types.js").read_text(encoding="utf-8")
    assert "@typedef {Object} StateResponse" in text
    assert "@typedef {Object} ReportResponse" in text


def test_api_types_js_parses_as_module() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not available for the parse check")
    script = (
        "const vm = require('node:vm');"
        "const fs = require('node:fs');"
        f"const src = fs.readFileSync({str(SRC_DIR / 'api-types.js')!r}, 'utf8');"
        "new vm.SourceTextModule(src, { identifier: 'api-types.js' });"
        "console.log('parse ok');"
    )
    result = subprocess.run(
        [node, "--experimental-vm-modules", "-e", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_module_graph_links() -> None:
    """Every import in the graph must resolve to a real exported name.

    Uses vm.SourceTextModule linking (parse + link, no evaluation) so a
    missing or misnamed export fails here instead of in the WebView.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not available for the link check")
    linker = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const srcDir = process.argv[1];
const files = [];
(function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) walk(p);
    else if (name.endsWith(".js")) files.push(p);
  }
})(srcDir);
const keyOf = (p) => "./" + path.relative(srcDir, p).replace(/\\/g, "/");
const modules = new Map();
async function main() {
  const context = vm.createContext({});
  for (const file of files) {
    const mod = new vm.SourceTextModule(fs.readFileSync(file, "utf8"), {
      identifier: keyOf(file), context,
    });
    modules.set(keyOf(file), mod);
  }
  const entry = modules.get("./main.js");
  assert.ok(entry, "main.js must exist");
  await entry.link((specifier, referencing) => {
    assert.ok(specifier.startsWith("."), `bare specifier ${specifier} in ${referencing.identifier}`);
    const target = "./" + path.posix.normalize(
      path.posix.join(path.posix.dirname(referencing.identifier), specifier));
    const mod = modules.get(target);
    assert.ok(mod, `${referencing.identifier} imports missing ${specifier}`);
    return mod;
  });
  console.log(`link ok: ${files.length} modules`);
}
main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
"""
    result = subprocess.run(
        [node, "--experimental-vm-modules", "-e", linker, str(SRC_DIR)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("module", _module_files(), ids=lambda p: p.name)
def test_shipped_modules_parse_as_esm(module: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not available for the parse check")
    script = (
        "const vm = require('node:vm');"
        "const fs = require('node:fs');"
        f"const src = fs.readFileSync({str(module)!r}, 'utf8');"
        f"new vm.SourceTextModule(src, {{ identifier: {module.name!r} }});"
    )
    result = subprocess.run(
        [node, "--experimental-vm-modules", "-e", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, f"{module.name}: {result.stdout}{result.stderr}"
