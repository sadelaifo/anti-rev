#!/usr/bin/env python3
"""
check_collisions — triage symbol_collision.py JSON output.

Reads the JSON produced by `symbol_collision.py --json` and prints:
  1. Any collision whose symbol or lib name matches a filter (default: UA_/open62541)
  2. Top "winner" libs among GLOBAL errors (the encrypted libs interposing)
  3. Top "loser" libs among GLOBAL errors (libs whose symbols are overridden)

Usage:
    symbol_collision.py /path/to/exe --enc-dir /path/to/libs/ --json > coll.json
    check_collisions.py coll.json
    check_collisions.py coll.json --filter protobuf
"""
from __future__ import annotations

import argparse
import collections
import json
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json_file", help="Output of symbol_collision.py --json")
    ap.add_argument("--filter", default="UA_,open62541",
                    help="Comma-separated substrings to match against sym/winner/loser "
                         "(default: UA_,open62541)")
    ap.add_argument("--top", type=int, default=20, help="Top N winners/losers to show")
    args = ap.parse_args()

    with open(args.json_file) as f:
        data = json.load(f)

    print(f"Loaded {len(data)} exe record(s) from {args.json_file}")

    filters = [s for s in args.filter.split(',') if s]

    # 1. Filtered collisions
    print(f"\n=== Collisions matching {filters} ===")
    found = 0
    for exe in data:
        for c in exe['collisions']:
            blob = c['sym'] + ' ' + c.get('winner', '') + ' ' + c.get('loser', '')
            if any(f in blob for f in filters):
                print(f"  [{exe['exe']}] {c['severity']:5s} {c['sym']}  "
                      f"winner={c.get('winner')}  loser={c.get('loser')}")
                found += 1
    print(f"  ({found} matches)")

    # 2. Top winners
    print(f"\n=== Top {args.top} GLOBAL-error winners (interposing libs) ===")
    ctr = collections.Counter()
    for exe in data:
        for c in exe['collisions']:
            if c['severity'] == 'error':
                ctr[c.get('winner', '?')] += 1
    for lib, n in ctr.most_common(args.top):
        print(f"  {n:6d}  {lib}")

    # 3. Top losers
    print(f"\n=== Top {args.top} GLOBAL-error losers (overridden libs) ===")
    ctr2 = collections.Counter()
    for exe in data:
        for c in exe['collisions']:
            if c['severity'] == 'error':
                ctr2[c.get('loser', '?')] += 1
    for lib, n in ctr2.most_common(args.top):
        print(f"  {n:6d}  {lib}")


if __name__ == '__main__':
    main()
