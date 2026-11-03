// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork attack tests (see docs/fork-attack-poc.md): the fork materialises exactly when the
//! number of equivocators exceeds f.

use std::num::NonZeroUsize;

use consensus::protocol::ConsensusProtocol;
use replica::config::ReplicaParameters;
use replica::result::{Outcome, RecoveryReport, RunResult};
use simulator::{ForkAttack, RecoveryConfig, SimulationConfig, SimulationRunner};

/// n=14, f=2, c=1: q=11, k=6, |D|=|B|=f+c=3. The worst-case layout for the counting lemma
/// keeps `e-f-1` equivocators unexposed and crashes `c` honest signers at the Alarm.
fn simulate(equivocators: usize, worst_case: bool, recovery: bool) -> RunResult<SimulationConfig> {
    let unexposed = if worst_case { equivocators - 3 } else { 0 };
    let config = SimulationConfig {
        committee_size: 14,
        duration_secs: 30,
        replica_parameters: ReplicaParameters {
            consensus: ConsensusProtocol::Orcaella {
                leader_count: NonZeroUsize::new(2).unwrap(),
                f: 2,
                c: 1,
            },
            ..Default::default()
        },
        fork_attack: Some(ForkAttack {
            equivocators,
            hidden: 3,
            b_side: 3 - unexposed,
            attack_start_round: 10,
            hide_delay_ms: 5000,
            twin_gap_ms: 0,
            unexposed,
            crashed: if worst_case { 1 } else { 0 },
            recovery: recovery.then_some(RecoveryConfig { delta_sync_ms: 200 }),
        }),
        ..Default::default()
    };
    SimulationRunner::new(config).run().unwrap()
}

fn run(equivocators: usize) -> Outcome {
    simulate(equivocators, false, false).outcome
}

fn recover(equivocators: usize, worst_case: bool) -> RecoveryReport {
    let result = simulate(equivocators, worst_case, true);
    assert_eq!(result.outcome, Outcome::Diverged);
    result.recovery.expect("recovery ran")
}

/// e = f: |A'| = k, so the others still indirect-commit twin A.
#[test]
fn fork_attack_e_equals_f_passes() {
    assert_eq!(run(2), Outcome::Pass);
}

/// e = f+1: D direct-commits twin A, the others indirect-commit twin B.
#[test]
fn fork_attack_e_equals_f_plus_1_diverges() {
    assert_eq!(run(3), Outcome::Diverged);
}

/// e = f+1, all equivocators double-block: every one is exposed, the finalized root keeps
/// q-e = 8 ChkProps against f+c = 3, and recovery takes 2Δ + (t+1)Δ plus the genesis round.
#[test]
fn recovery_at_e_equals_f_plus_1_restores_the_finalized_root() {
    let report = recover(3, false);
    assert_eq!(report.rounds, 9);
    assert_eq!(report.exposed, 3);
    assert!(report.exposed_only_byzantine);
    assert_eq!((report.count_finalized, report.count_conflicting), (8, 3));
    assert_eq!(report.finalized_recovered, Some(true));
    assert!(report.agreement);
    let recovery_ms = report
        .recovery_ms
        .expect("every correct replica forms the GenesisQC");
    assert!((2200..2500).contains(&recovery_ms), "{recovery_ms} ms");
}

/// Worst case at e = 2f: f+1 exposed, the finalized root keeps q-e-c = 6 against f+c+(e-f-1) = 4.
#[test]
fn recovery_worst_case_at_e_equals_2f_restores_the_finalized_root() {
    let report = recover(4, true);
    assert_eq!(report.exposed, 3);
    assert_eq!((report.count_finalized, report.count_conflicting), (6, 4));
    assert_eq!(report.finalized_recovered, Some(true));
    assert!(report.agreement);
}

/// Worst case at e = 2f+1: the count ties 5-5 at the fork height, the counting step stops,
/// and the lowest-digest VoteQC fallback picks the other twin, as the impossibility predicts.
#[test]
fn recovery_worst_case_at_e_equals_2f_plus_1_ties() {
    let report = recover(5, true);
    assert_eq!(report.exposed, 3);
    assert_eq!((report.count_finalized, report.count_conflicting), (5, 5));
    assert_eq!(report.break_height, report.fork_height);
    assert_eq!(report.finalized_recovered, Some(false));
    assert!(report.agreement);
}
