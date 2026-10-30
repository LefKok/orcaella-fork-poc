// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork attack tests (see docs/fork-attack-poc.md): the fork materialises exactly when the
//! number of equivocators exceeds f.

use std::num::NonZeroUsize;

use consensus::protocol::ConsensusProtocol;
use replica::config::ReplicaParameters;
use replica::result::Outcome;
use simulator::{ForkAttack, SimulationConfig, SimulationRunner};

/// n=14, f=2, c=1: q=11, k=6, |D|=|B|=f+c=3.
fn run(equivocators: usize) -> Outcome {
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
            b_side: 3,
            attack_start_round: 10,
            hide_delay_ms: 5000,
        }),
        ..Default::default()
    };
    SimulationRunner::new(config).run().unwrap().outcome
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
