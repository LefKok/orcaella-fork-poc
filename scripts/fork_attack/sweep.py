#!/usr/bin/env python3
"""Sweep the fork attack over the number of equivocators e (see docs/fork-attack-poc.md).

For each (f, c) the committee is the minimal n = 5f+3c+1; e runs from f-1 to n-2f-2c-1,
the last point being the largest e at which the Resilient Path must still be safe. Pass
`--include-break` to also run e = n-2f-2c, where the Resilient Path is expected to fail (the
simulator may panic with "More than one certified block"; that is reported as such).

Usage: scripts/fork_attack/sweep.py [--points 2,1 3,2] [--duration 30] [--out results/fork]
"""
import argparse
import pathlib
import subprocess
import sys

try:
    import yaml
except ImportError:  # PyYAML is optional: fall back to a two-level parser for meta.yaml
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parents[2]


def config(f, c, e, duration, seed):
    n = 5 * f + 3 * c + 1
    q = n - f - c
    return f"""name: fork-f{f}-c{c}-e{e}
committee_size: {n}
duration_secs: {duration}
rng_seed: {seed}
topology: fullMesh
fork_attack:
  equivocators: {e}
  hidden: {f + c}
  b_side: {n - q}
  attack_start_round: 10
  hide_delay_ms: 5000
replica_parameters:
  consensus:
    protocol: orcaella
    leader_count: 2
    f: {f}
    c: {c}
load_generator:
  load: 100
  transaction_size: 512
  initial_delay: 0s
"""


def load_meta(text):
    if yaml is not None:
        return yaml.safe_load(text)
    data, section = {}, None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if line.startswith(" "):
            section[key.strip()] = None if value in ("null", "~", "") else (int(value) if value.isdigit() else value)
        elif value == "":
            section = data[key] = {}
        else:
            data[key] = int(value) if value.isdigit() else value
    return data


def run(cfg, out):
    out.mkdir(parents=True, exist_ok=True)
    path = out / "config.yaml"
    path.write_text(cfg)
    meta = out / "meta.yaml"
    meta.unlink(missing_ok=True)
    proc = subprocess.run(
        ["cargo", "run", "--release", "-q", "--", "simulate", "--config-path", str(path),
         "--output-dir", str(out)],
        cwd=ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 and not meta.exists():
        reason = "panic: more than one certified block" if "More than one certified block" in proc.stderr else f"exit {proc.returncode}"
        return reason, "-"
    data = load_meta(meta.read_text()) if meta.exists() else {}
    outcome = data.get("outcome", "?")
    res = data.get("resilient")
    if isinstance(res, dict):
        fork = res.get("first_fork_height")
        resilient = "unique" if fork is None else f"FORK@{fork} ({res.get('forked_heights')} heights)"
    else:
        resilient = str(res)
    return str(outcome), resilient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--points", nargs="*", default=["2,1", "3,2"])
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="results/fork")
    ap.add_argument("--include-break", action="store_true")
    args = ap.parse_args()

    rows = []
    for point in args.points:
        f, c = (int(x) for x in point.split(","))
        n = 5 * f + 3 * c + 1
        e_max = n - 2 * f - 2 * c - (0 if args.include_break else 1)
        for e in range(max(1, f - 1), e_max + 1):
            outcome, resilient = run(config(f, c, e, args.duration, args.seed),
                                     ROOT / args.out / f"f{f}-c{c}-e{e}")
            expect = "break" if e == n - 2 * f - 2 * c else "fork" if e > f else "safe"
            rows.append((f, c, n, e, expect, outcome, resilient))
            print(f"f={f} c={c} n={n} e={e:2d} expect={expect:4s} outcome={outcome:11s} resilient={resilient}",
                  flush=True)

    print("\n f  c   n   e  expect  outcome      resilient")
    for f, c, n, e, expect, outcome, resilient in rows:
        print(f"{f:2d} {c:2d} {n:3d} {e:3d}  {expect:6s}  {outcome:11s}  {resilient}")
    # Fast path: diverged iff e > f. Resilient Path: unique below the break point; at the
    # break both twins are certified and the committer panics (or the emulation reports a fork).
    def ok(f, c, n, e, expect, outcome, resilient):
        if expect == "break":
            return outcome.startswith("panic") or resilient.startswith("FORK")
        return (outcome == "diverged") == (expect == "fork") and resilient == "unique"

    bad = [r for r in rows if not ok(*r)]
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
