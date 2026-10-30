# Fork-attack PoC: breaking Orcaella's indirect rule at e = f+1 equivocators

Status: proof of concept, simulator only. Replica (consensus/dag) code stays unmodified except
one test-util helper on `Block`.

## Goal

Demonstrate empirically, in the discrete-event simulator, the tightness argument of the paper
(Theorem 1, Exclusivity) on the DAG instantiation:

- With `e = f` equivocators the attack below cannot fork: the run ends `Pass` or `NoProgress`.
- With `e = f+1 .. n-2f-2c-1` it forks the fast path: `Outcome::Diverged`, while the emulated
  Resilient Path (checkpoint certificates) stays unique per height.
- At `e = n-2f-2c` the Resilient Path also breaks (two checkpoint certificates at one height).
  In the simulator this manifests as the `try_direct_decide` panic "More than one certified
  block" on some replica; that is acceptable evidence for the PoC, do not change consensus code.

Orcaella thresholds in code (`crates/consensus/src/protocol/orcaella.rs`):
`q = n-f-c` (direct commit), `direct_skip = 4f+2c+1`, `anchor_link_size = n-3f-2c` (weak
certificate for the indirect rule), wave length 2, pipelined, 2 leaders per round, round-robin
`leader(round, offset) = (round + offset) mod n`.

Use exactly `n = 5f+3c+1` for the PoC (then `anchor_link_size = k = 2f+c+1`, `direct_skip = q`).
Default committee: `f=2, c=1, n=14, q=11, k=6`.

## The attack (one leader slot R, led by equivocator L = authority 0)

Partition the committee by index. L = 0; the remaining equivocators sit at the *end* of the
index range so that the round-robin leaders right after R (authorities 1, 2, ...) are honest
A' members, whose R+2 blocks serve as the anchor:

| set | indices | size | role |
|---|---|---|---|
| L | `0` | 1 | equivocating leader of slot R |
| A' | `1 .. n-e+1-2(f+c)` | n-2f-2c-e | honest, support twin A, not hidden |
| B | next `f+c` | f+c | honest, support twin B |
| D | next `f+c` | f+c | honest, "hidden": their round-(R+1) votes to non-D peers are delayed by `hide_delay` |
| E \ L | `n-e+1 .. n` | e-1 | equivocators |

`H_A = D ∪ A'` has `q-e` members. "Others" = `A' ∪ B ∪ E` has `n-(f+c) = q` members, so they can
advance rounds without D.

Naming: L's *native* round-R block is twin B; twin A is the digest-flipped copy. This way every
equivocator's native round-(R+1) vote (the one its own later blocks reference) supports twin B,
which is what the others must see; only the copies sent to D are rewritten. The only block
reflected into its author's own DAG is twin A into L (the store indexes it as a regular block,
not as L's own), so L can process the honest votes that reference it and keep proposing.

Network shim behaviour (all on the sender's outgoing links, `crates/simulator/src/fork_attack.rs`):

1. **Leader twins.** L's own block at round R is sent to *every* peer as two messages on the
   same FIFO link, so nobody waits on a missing parent (the DAG's missing-block fetch has a
   15 s grace period): peers in `D ∪ A'` get twin A then twin B; peers in `B ∪ E` get twin B
   then twin A. Includes are assembled in arrival order and support is the first `(L, R)`
   reference, so each peer's vote supports the twin delivered first.
2. **Vote equivocation.** Every `x ∈ E` produces one native round-(R+1) block whose first
   `(L, R)` reference is twin B. The shim sends it unchanged to every peer outside `D`; peers in
   `D` get the A-version first (the same block with that reference's digest flipped to twin A
   and the block digest flipped) and then the native vote as well, so D stays causally complete
   when the others' later blocks reference the native votes (the simulator never fetches
   missing parents on demand: `enable_synchronizer` is off). D's support counts are unaffected:
   the A-versions still give twin A `q` supports at D, while twin B gets `f+c+e`, which reaches
   `q` only at the break point `e = n-2f-2c` (where D then sees two certified twins and the
   committer panics: the expected signature there). Peers outside `D` also receive the
   A-version, but only after `hide_delay`, once slot R is decided; without it D's later blocks
   (which reference the A-versions) would stay suspended at the others for the rest of the run
   and every D-led leader round would burn a leader timeout. Only x's own round-(R+1) block is
   rewritten; everything else passes.
3. **Hiding D.** For `from ∈ D`, `to ∉ D`: delay D's round-(R+1) votes by `hide_delay`
   (default 5 s, must exceed the time from D's R+1 vote to the others' R+2 proposals, which fix
   the anchor's history). D's later blocks arrive on time but stay suspended behind the missing
   R+1 parents, so they cannot enter the anchor's history either; once the votes land, D
   rejoins and the DAG heals. Everything else from D flows normally, so the run is not slowed
   before R, and D's late votes never alter an already decided prefix.

Why it forks at `e = f+1` (minimal n):

- D members see all of `H_A`'s R+1 votes (q-e) plus E's A-versions (e): q supports for A, so
  they **direct-commit A** as soon as round R+1 completes.
- Others see A' (q-e-f-c = n-2f-2c-e supports for A, fewer than k iff e > f), B's votes and E's
  B-versions (f+c+e supports for B, at least k iff e ≥ f+1). No direct decision (A lacks q,
  blames for A are f+c+e < direct_skip for e < n-2f-2c). The next leader at round ≥ R+2 among
  "others" is direct-committed at R+3 and becomes the anchor; its causal history holds a weak
  certificate for B only, so others **indirect-commit B**. Slot R diverges.
- At `e = f` the anchor's history holds `|A'| = n-3f-2c = k` supports for A (weakly certified)
  and only `2f+c < k` for B, so others indirect-commit A as well: consistent, `Pass`. This is
  the Exclusion lemma holding with equality, and the control point of the sweep.

Pick R as the smallest leader round `≥ attack_start_round` (config, default 10) with
`(R + 0) mod n == 0`, i.e. L holds leader offset 0 at R. Slots at other rounds are unaffected:
before R nothing is delayed or rewritten, and after R the others decide without D.

## Config

`SimulationConfig` gets

```yaml
fork_attack:
  equivocators: 3        # e; L = 0 plus the last e-1 indices
  hidden: 3              # |D| = f + c
  b_side: 3              # |B| = n - q = f + c ; A' is whatever remains up to q
  attack_start_round: 10
  hide_delay_ms: 5000
```

Validate on load: `equivocators + hidden + a_prime + b_side == n`, `b_side == hidden`,
`equivocators >= 1`. `fork_attack` and `equivocating_leaders` are mutually exclusive.

## Resilient Path emulation (post-hoc, no checkpoint engine)

In `crates/replica/src/result.rs`, next to `Outcome`: from the per-replica committed streams,
the existing `PrefixHasher` cumulative hash at prefix length `h` is that replica's state root at
height `h`. Emulate the checkpoint engine's counting:

- Honest replica `i ∉ E` attests `(h, root_i(h))` for every height it reached.
- Each equivocator attests every distinct root observed at height `h` across all replicas (AbC
  behaviour, worst case).
- A checkpoint certificate exists for `(h, root)` iff the number of attesting authorities is
  `≥ q`.

Output `ResilientOutcome { heights_with_two_certificates: usize, first_fork_height: Option<usize> }`
and print it with the outcome. Needs `q` and the equivocator index set, passed from the config.

## Sweep

`scripts/fork_attack/sweep.py`: for `(f,c) ∈ {(2,1), (3,2)}`, `n = 5f+3c+1`, `e` from `f-1` to
`n-2f-2c-1`, write the YAML, run `cargo run --release -- simulate --config-path <yaml>
--output-dir <dir>`, read `meta.yaml` (outcome) and the resilient outcome, print one table:
`f c n e | outcome | resilient`. Expected: Diverged exactly for `e ≥ f+1`; resilient unique
throughout this range. Run `e = n-2f-2c` once and report the panic as the resilient-path break.

## Non-goals

No fork detection, no Alarm, no recovery, no real checkpoint messages, no stake weighting, no
production hardening. Minimise lines; prefer one new file `crates/simulator/src/fork_attack.rs`
plus small edits to `network.rs`, `config.rs`, `runner.rs`, `result.rs`, the simulate command,
and a test in `crates/simulator/tests/fork_attack.rs`.
