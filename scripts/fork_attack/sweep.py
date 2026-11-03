#!/usr/bin/env python3
"""Sweep the fork attack over the number of equivocators e (see docs/fork-attack-poc.md).

For each (f, c) the committee is the minimal n = 5f+3c+1; e runs from f-1 to n-2f-2c-1,
the last point being the largest e at which the Resilient Path must still be safe. Pass
`--include-break` to also run e = n-2f-2c, where the Resilient Path is expected to fail (the
simulator may panic with "More than one certified block"; that is reported as such).

With `--recovery` every point also runs the fork recovery (Algorithm 2) with the given
Δ_sync and reports its outcome; `--worst-case` lays the attack out as in the proof of the
counting lemma (b-f-1 Byzantine replicas vote honestly and expose nothing, c honest signers
crash at the Alarm), which is possible for e <= 2f+c+1 and is where the count ties at
e = 2f+1.

Usage: scripts/fork_attack/sweep.py [--points 2,1 3,2] [--duration 30] [--out results/fork]
       [--recovery [DELTA_SYNC_MS]] [--worst-case] [--seed N]
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


def config(f, c, e, duration, seed, recovery=None, worst_case=False):
    n = 5 * f + 3 * c + 1
    q = n - f - c
    unexposed = max(0, e - f - 1) if worst_case else 0
    crashed = c if worst_case else 0
    extra = f"  unexposed: {unexposed}\n  crashed: {crashed}\n"
    if recovery is not None:
        extra += f"  recovery:\n    delta_sync_ms: {recovery}\n"
    return f"""name: fork-f{f}-c{c}-e{e}
committee_size: {n}
duration_secs: {duration}
rng_seed: {seed}
topology: fullMesh
fork_attack:
  equivocators: {e}
  hidden: {f + c}
  b_side: {n - q - unexposed}
  attack_start_round: 10
  hide_delay_ms: 5000
{extra}replica_parameters:
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
        return reason, "-", None
    data = load_meta(meta.read_text()) if meta.exists() else {}
    outcome = data.get("outcome", "?")
    res = data.get("resilient")
    if isinstance(res, dict):
        fork = res.get("first_fork_height")
        resilient = "unique" if fork is None else f"FORK@{fork} ({res.get('forked_heights')} heights)"
    else:
        resilient = str(res)
    rec = data.get("recovery")
    return str(outcome), resilient, rec if isinstance(rec, dict) else None


def recovery_summary(rec):
    if rec is None:
        return "-"
    if rec.get("recovery_ms") is None:
        return "incomplete"
    return (f"recovered={rec.get('finalized_recovered')} count={rec.get('count_finalized')}:"
            f"{rec.get('count_conflicting')} E={rec.get('exposed')} "
            f"t={rec.get('recovery_ms')}ms in={rec.get('input_bytes_max')}B "
            f"sent={rec.get('sent_bytes_max')}B agree={rec.get('agreement')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--points", nargs="*", default=["2,1", "3,2"])
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="results/fork")
    ap.add_argument("--include-break", action="store_true")
    ap.add_argument("--recovery", nargs="?", const=200, type=int, default=None,
                    metavar="DELTA_SYNC_MS")
    ap.add_argument("--worst-case", action="store_true")
    args = ap.parse_args()

    rows = []
    for point in args.points:
        f, c = (int(x) for x in point.split(","))
        n = 5 * f + 3 * c + 1
        e_max = n - 2 * f - 2 * c - (0 if args.include_break else 1)
        if args.worst_case:
            e_max = min(e_max, 2 * f + c + 1)
        for e in range(max(1, f - 1), e_max + 1):
            cfg = config(f, c, e, args.duration, args.seed, args.recovery, args.worst_case)
            outcome, resilient, rec = run(cfg, ROOT / args.out / f"f{f}-c{c}-e{e}")
            expect = "break" if e == n - 2 * f - 2 * c else "fork" if e > f else "safe"
            rows.append((f, c, n, e, expect, outcome, resilient, rec))
            print(f"f={f} c={c} n={n} e={e:2d} expect={expect:4s} outcome={outcome:11s} "
                  f"resilient={resilient} recovery={recovery_summary(rec)}", flush=True)

    print("\n f  c   n   e  expect  outcome      resilient  recovery")
    for f, c, n, e, expect, outcome, resilient, rec in rows:
        print(f"{f:2d} {c:2d} {n:3d} {e:3d}  {expect:6s}  {outcome:11s}  {resilient:8s}  "
              f"{recovery_summary(rec)}")

    # Fast path: diverged iff e > f. Resilient Path: unique below the break point; at the
    # break both twins are certified and the committer panics (or the emulation reports a fork).
    # Recovery (when run, on forked points): the finalized root is recovered in the plain
    # layout, and in the worst-case layout exactly for e <= 2f.
    def ok(f, c, n, e, expect, outcome, resilient, rec):
        if expect == "break":
            return outcome.startswith("panic") or resilient.startswith("FORK")
        if (outcome == "diverged") != (expect == "fork") or resilient != "unique":
            return False
        if args.recovery is None or expect != "fork":
            return True
        if rec is None or rec.get("recovery_ms") is None or not rec.get("agreement"):
            return False
        recovered = rec.get("finalized_recovered")
        return recovered == (e <= 2 * f) if args.worst_case else recovered is True

    bad = [r for r in rows if not ok(*r)]
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
