"""Validate release refs and preserve curated notes when they are available."""

import argparse
from pathlib import Path
import re
import tomllib


def validate_ref(ref_name, ref_type, root):
    prefixes = {"tag": "v", "branch": "release-"}
    if ref_type not in prefixes:
        raise ValueError(f"unsupported ref type: {ref_type}")
    prefix = prefixes[ref_type]
    if not ref_name.startswith(prefix):
        raise ValueError(f"expected a ref starting with {prefix!r}, got {ref_name}")
    ref_version = ref_name[len(prefix):]
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_version = cargo["workspace"]["package"]["version"]
    if ref_version != workspace_version:
        raise ValueError(
            f"ref version {ref_version} does not match workspace version {workspace_version}"
        )
    return ref_version


def release_notes(version, root):
    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        return ""
    pattern = re.compile(rf"^## \[{re.escape(version)}\]\s+-\s+.+$")
    capture = []
    for line in changelog.read_text(encoding="utf-8").splitlines():
        if line.startswith("## ["):
            if capture:
                break
            if pattern.match(line):
                capture.append(line)
        elif capture:
            capture.append(line)
    return "\n".join(capture).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref_name")
    parser.add_argument("ref_type", choices=("tag", "branch"))
    parser.add_argument("--notes-file", type=Path)
    args = parser.parse_args()
    try:
        version = validate_ref(args.ref_name, args.ref_type, Path.cwd())
    except ValueError as error:
        parser.error(str(error))
    if args.notes_file:
        notes = release_notes(version, Path.cwd())
        args.notes_file.write_text(notes + "\n" if notes else "", encoding="utf-8")


if __name__ == "__main__":
    main()
