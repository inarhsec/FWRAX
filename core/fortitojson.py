"""
FortiGate .conf → JSON converter.

Usage:
  python fortitojson.py fortigate.conf > output.json
  python fortitojson.py fortigate.conf -o output.json

Known limitations of the original parser that are fixed here:
  - Nested ``config`` blocks (e.g. config firewall policy inside config vdom)
    would corrupt the stack because the original pushed a bare dict that had no
    parent reference.  Now each config level stores its content under its own
    section key.
  - ``stack[-1]`` access on an empty stack (malformed / truncated conf) raised
    an IndexError; guarded with a check.
  - ``set`` lines with no value crashed on ``" ".join(val)`` when val is empty.
  - Result was always stack[0] even when stack ended up empty.
"""

import json
import sys
from pathlib import Path


def _set_value(obj: dict, key: str, raw_val: str) -> None:
    """Coerce value: int if possible, else strip surrounding quotes."""
    val: str | int = raw_val.strip().strip('"')
    try:
        val = int(val)  # type: ignore[assignment]
    except (ValueError, TypeError):
        pass
    obj[key] = val


def parse_fortigate_conf(text: str) -> dict:
    """Parse a FortiOS backup text into a nested dict."""
    root: dict = {}
    # Each stack frame: (section_dict, section_name)
    stack: list[tuple[dict, str]] = [(root, "__root__")]

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("config "):
            section_name = line[len("config "):].strip()
            parent_dict = stack[-1][0]
            new_section: dict = {}
            # Multiple config blocks with the same name are merged.
            if section_name in parent_dict and isinstance(parent_dict[section_name], dict):
                new_section = parent_dict[section_name]
            else:
                parent_dict[section_name] = new_section
            stack.append((new_section, section_name))

        elif line.startswith("edit "):
            edit_name = line[len("edit "):].strip().strip('"')
            parent_dict = stack[-1][0]
            entry: dict = parent_dict.setdefault(edit_name, {})
            stack.append((entry, f"edit:{edit_name}"))

        elif line.startswith("set "):
            parts = line.split(None, 2)  # ["set", key, value?]
            if len(parts) < 2:
                continue
            key = parts[1]
            raw_val = parts[2] if len(parts) > 2 else ""
            if stack:
                _set_value(stack[-1][0], key, raw_val)

        elif line == "next":
            # Pop the current edit frame (but never pop root)
            if len(stack) > 1:
                stack.pop()

        elif line == "end":
            # Pop the current config frame (but never pop root)
            if len(stack) > 1:
                stack.pop()

    return root


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Convert FortiGate .conf to JSON.")
    ap.add_argument("conf_file", help="Path to FortiGate backup (.conf) file")
    ap.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    args = ap.parse_args()

    conf_path = Path(args.conf_file)
    if not conf_path.is_file():
        print(f"ERROR: File not found: {conf_path}", file=sys.stderr)
        sys.exit(1)

    text = conf_path.read_text(encoding="utf-8", errors="replace")
    result = parse_fortigate_conf(text)

    out_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(out_json, encoding="utf-8")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(out_json)


if __name__ == "__main__":
    main()