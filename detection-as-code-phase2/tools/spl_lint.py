"""
Lint Splunk SPL output for operator-precedence bugs.

pySigma's Splunk backend sometimes emits queries like:

    A=x OR B=y AND C=z

where the original Sigma condition was `(A=x OR B=y) AND C=z`. Splunk
parses implicit/explicit AND with higher precedence than OR, so the
emitted query silently changes meaning to `A=x OR (B=y AND C=z)`,
which alerts on `A=x` alone with no other constraint — a serious FP
risk and a real-world detection-engineering footgun.

This linter scans converted .conf savedsearch stanzas for unparenthesized
OR groups with AND siblings on the search line and flags them.

Usage:
    python tools/spl_lint.py build/splunk/
"""

from __future__ import annotations

import argparse
import configparser
import re
import sys
from pathlib import Path


def extract_search_line(path: Path) -> str | None:
    """Pull just the `search = ...` line from a savedsearch stanza."""
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(path, encoding="utf-8")
    for section in parser.sections():
        if parser.has_option(section, "search"):
            return parser.get(section, "search")
    return None


def has_unsafe_or(spl: str) -> bool:
    """
    Return True if the SPL has a top-level `OR` next to terms that aren't
    grouped with parens, when other AND-style siblings exist outside the
    OR group.

    Heuristic: if the query contains ` OR ` AND there is at least one
    standalone `key=value` or `key IN(...)` term following the OR group
    that is NOT inside parentheses, the precedence is ambiguous.

    This is intentionally conservative — false positives on this lint are
    fine; missed bugs are not. A flagged rule should be reviewed by a human.
    """
    if " OR " not in spl:
        return False

    # Strip the leading event-source / index filters that don't participate
    # in the boolean tree (e.g. `eventtype=foo` prefixes pySigma sometimes
    # emits). We focus on what comes after the first non-trivial token.
    body = spl.strip()

    # Walk the string and track parenthesis depth. If we hit ` OR ` at
    # depth 0 and later hit ` ` (implicit AND) or ` AND ` at depth 0,
    # that is the unsafe shape.
    depth = 0
    seen_or_at_depth_0 = False
    seen_and_after_or = False
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and body[i : i + 4] == " OR ":
            seen_or_at_depth_0 = True
            i += 4
            continue
        elif depth == 0 and seen_or_at_depth_0:
            # Look for an implicit AND (a space-separated `key=value` or `key IN`)
            # OR an explicit ` AND ` token at depth 0
            if body[i : i + 5] == " AND ":
                seen_and_after_or = True
                break
            # Implicit AND detection: at depth 0 we see a space followed
            # by a non-`OR`/`AND` token that looks like a field comparison.
            if ch == " " and re.match(
                r"\s+\w+(\s*[=!<>]+|\s+IN\s*\(|\|)", body[i:]
            ):
                # Make sure it's not the start of ` OR ` or ` AND `
                if body[i : i + 4] != " OR " and body[i : i + 5] != " AND ":
                    seen_and_after_or = True
                    break
        i += 1

    return seen_or_at_depth_0 and seen_and_after_or


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()

    if not args.build_dir.exists():
        print(f"ERROR: {args.build_dir} not found", file=sys.stderr)
        return 2

    confs = sorted(args.build_dir.glob("*.conf"))
    if not confs:
        print(f"WARNING: no .conf files in {args.build_dir}")
        return 0

    flagged: list[Path] = []
    for path in confs:
        spl = extract_search_line(path)
        if spl is None:
            continue
        if has_unsafe_or(spl):
            flagged.append(path)
            print(f"  [WARN] {path.name}: unparenthesized OR with AND siblings detected")
            print(f"         search: {spl[:200]}{'...' if len(spl) > 200 else ''}")

    print()
    if flagged:
        print(
            f"{len(flagged)} rule(s) need review. See docs/known_issues.md for guidance.",
            file=sys.stderr,
        )
        # Exit 0 by default — this is a warning, not a hard fail. Set
        # SPL_LINT_STRICT=1 to fail CI on warnings.
        if __import__("os").environ.get("SPL_LINT_STRICT") == "1":
            return 1
    else:
        print(f"OK: {len(confs)} rule(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
