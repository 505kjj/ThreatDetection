"""Build a reproducible ZIP containing only the production Manifest V3 extension."""

import hashlib
import json
from pathlib import Path
import re
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


EXTENSION = Path(__file__).resolve().parents[1] / "extension"
FILES = """
backend-api.mjs
background.js
block-rules.mjs
browser-protection.mjs
content.js
financial-domains.mjs
fonts/Inter-OFL.txt
fonts/inter-latin.woff2
icons/icon128.png
icons/icon16.png
icons/icon48.png
icons/mark.svg
impersonation.mjs
login-risk.mjs
manifest.json
options.html
options.js
popup.html
popup.js
reputation.mjs
settings.mjs
styles.css
theme.css
threat-reporting.mjs
vendor/confusables.mjs
vendor/public-suffix-list.LICENSE.txt
vendor/punycode.LICENSE.txt
vendor/punycode.mjs
vendor/tldts.LICENSE.txt
vendor/tldts.mjs
vendor/unicode.LICENSE.txt
warning.css
warning.html
warning.mjs
""".split()


def package(directory):
    manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    if manifest["manifest_version"] != 3 or not re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
        raise ValueError("Expected a versioned Manifest V3 extension")

    contents = {}
    for name in sorted(FILES):
        path = EXTENSION / name
        if not path.resolve(strict=True).is_relative_to(EXTENSION):
            raise ValueError(f"Asset resolves outside the extension directory: {name}")
        contents[name] = path.read_bytes()

    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"ThreatDetection-{version}.zip"
    with ZipFile(target, "x") as archive:
        for name, data in contents.items():
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, ZIP_DEFLATED, compresslevel=9)
    with ZipFile(target) as archive:
        if archive.testzip() is not None or archive.namelist() != list(contents):
            raise ValueError("Release archive integrity check failed")
    print(f"{target}\n{len(contents)} files, {target.stat().st_size:,} bytes")
    print(f"SHA-256 {hashlib.sha256(target.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/package-extension.py <output-directory>")
    package(Path(sys.argv[1]).resolve())
