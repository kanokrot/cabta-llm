from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_theme_toggle_flips_data_theme_with_blocked_storage() -> None:
    root = Path(__file__).parents[1]
    theme_js = root / "static" / "js" / "theme.js"
    harness = r"""
const fs = require('fs');
const vm = require('vm');

let theme = 'dark';
const document = {
    readyState: 'complete',
    documentElement: { setAttribute: (name, value) => { if (name === 'data-theme') theme = value; } },
    addEventListener: () => {},
    querySelector: () => null,
};
const window = {
    matchMedia: () => ({ matches: false, addEventListener: () => {} }),
    Chart: null,
};
const blockedStorage = {
    getItem: () => { throw new Error('storage blocked'); },
    setItem: () => { throw new Error('storage blocked'); },
};

vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
    document,
    window,
    localStorage: blockedStorage,
});

if (theme !== 'dark') throw new Error('theme initialization failed: ' + theme);
window.MCPTheme.toggle();
if (theme !== 'light') throw new Error('first toggle failed: ' + theme);
window.MCPTheme.toggle();
if (theme !== 'dark') throw new Error('second toggle failed: ' + theme);
"""
    result = subprocess.run(
        ["node", "-e", harness, str(theme_js)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, json.dumps(
        {"stdout": result.stdout, "stderr": result.stderr}
    )


def test_both_base_templates_use_the_theme_toggle_handler() -> None:
    root = Path(__file__).parents[1]
    base = (root / "templates" / "base.html").read_text(encoding="utf-8")
    auth = (root / "templates" / "base_auth.html").read_text(encoding="utf-8")

    assert 'onclick="MCPTheme.toggle()"' in base
    assert 'onclick="MCPTheme.toggle()"' in auth
