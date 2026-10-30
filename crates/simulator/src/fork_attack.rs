// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork attack shim (see docs/fork-attack-poc.md): `e` equivocators plus pre-GST hiding of
//! `f + c` honest replicas fork the Fast Path exactly when `e > f`.
//!
//! Roles: `L = 0` leads slot `R`; `E` = `L` plus the trailing equivocators; `D` hidden honest;
//! `A'` honest supporting twin A; `B` honest supporting twin B. L's native round-`R` block is
//! "twin B" and goes to `B ∪ E`; the digest-flipped "twin A" goes to `D ∪ A'`. Every
//! equivocator's native round-`R+1` vote therefore supports twin B; the copy sent to `D` is
//! rewritten to reference twin A. `D`'s round-`R+1` votes to non-`D` replicas are delayed.

use std::{
    collections::VecDeque,
    ops::{Range, RangeInclusive},
    sync::Arc,
    time::Duration,
};

use consensus::leader::{LeaderElection, LeaderElector};
use dag::authority::Authority;
use dag::block::{Block, BlockReference, RoundNumber, data::Data};
use dag::context::Ctx;
use dag::crypto::{BLOCK_DIGEST_SIZE, BlockDigest};
use dag::sync::network::NetworkMessage;
use tokio::sync::mpsc;

use crate::config::ForkAttack;
use crate::context::SimulatorContext;
use crate::executor::Sleep;

pub(crate) struct ForkAttacker {
    n: usize,
    equivocators: usize,
    hidden: Range<usize>,
    a_prime: Range<usize>,
    attack_round: RoundNumber,
    hide_delay: Duration,
}

impl ForkAttacker {
    /// Panics if the attack configuration is invalid.
    pub(crate) fn new(config: &ForkAttack, n: usize, leader_election: LeaderElection) -> Self {
        config.validate(n).expect("invalid fork attack config");
        let elector = LeaderElector::new(n, leader_election);
        let attack_round = (config.attack_start_round..)
            .find(|&r| elector.elect_leader(r, 0) == Authority::from(0usize))
            .expect("authority 0 leads some round");
        let hidden = config.hidden_indices(n);
        Self {
            n,
            equivocators: config.equivocators,
            a_prime: config.a_prime_indices(n),
            hidden,
            attack_round,
            hide_delay: config.hide_delay(),
        }
    }

    /// The computed attack round R.
    pub(crate) fn attack_round(&self) -> RoundNumber {
        self.attack_round
    }

    pub(crate) fn is_equivocator(&self, index: usize) -> bool {
        index == 0 || index >= self.n + 1 - self.equivocators
    }

    fn is_hidden(&self, index: usize) -> bool {
        self.hidden.contains(&index)
    }

    /// Whether the `sender -> receiver` link hides `sender` (D -> non-D). Only D's round-(R+1)
    /// votes are delayed on such links; D's later blocks arrive on time but stay suspended
    /// behind them, and everything else flows normally.
    pub(crate) fn should_delay(&self, sender: usize, receiver: usize) -> bool {
        self.is_hidden(sender) && !self.is_hidden(receiver)
    }

    fn flip_digest(digest: BlockDigest) -> BlockDigest {
        let mut bytes = [0u8; BLOCK_DIGEST_SIZE];
        bytes.copy_from_slice(digest.as_ref());
        bytes[BLOCK_DIGEST_SIZE - 1] ^= 1;
        BlockDigest::from(bytes)
    }

    /// Rewrite the vote's first (L, R) reference to twin A and re-digest the block.
    fn to_twin_a_vote(&self, block: &Data<Block>) -> Data<Block> {
        let leader_slot = (Authority::from(0usize), self.attack_round);
        let mut replaced = false;
        let includes = block
            .includes()
            .iter()
            .filter_map(|include| {
                if include.author_round() != leader_slot {
                    return Some(*include);
                }
                if replaced {
                    return None;
                }
                replaced = true;
                Some(BlockReference {
                    authority: include.authority,
                    round: include.round,
                    digest: Self::flip_digest(include.digest),
                })
            })
            .collect();
        Data::new(
            Block::clone(block)
                .with_includes(includes)
                .with_digest(Self::flip_digest(block.digest())),
        )
    }

    /// Twin A of L's round-R block, if `message` is L sending that block.
    pub(crate) fn leader_twin_a(
        &self,
        message: &NetworkMessage,
        sender: usize,
    ) -> Option<NetworkMessage> {
        let NetworkMessage::Block(block) = message else {
            return None;
        };
        (sender == 0
            && block.author() == Authority::from(0usize)
            && block.round() == self.attack_round)
            .then(|| {
                let twin_a = Block::clone(block).with_digest(Self::flip_digest(block.digest()));
                NetworkMessage::Block(Data::new(twin_a))
            })
    }

    /// Rewrite an outgoing message from an equivocator on the `sender -> receiver` link.
    /// Returns the messages to deliver now and, optionally, one to deliver after `hide_delay`.
    pub(crate) fn rewrite(
        &self,
        message: NetworkMessage,
        sender: usize,
        receiver: usize,
    ) -> (Vec<NetworkMessage>, Option<Data<Block>>) {
        let NetworkMessage::Block(block) = &message else {
            return (vec![message], None);
        };
        // L's round-R block: every peer gets both twins, so nobody waits on a missing parent;
        // the first-delivered twin is the one the peer's vote supports. D ∪ A' get twin A
        // first, everyone else the native block (twin B) first.
        if let Some(twin_a) = self.leader_twin_a(&message, sender) {
            let both = if self.a_prime.contains(&receiver) || self.is_hidden(receiver) {
                vec![twin_a, message]
            } else {
                vec![message, twin_a]
            };
            return (both, None);
        }
        // An equivocator's own round-(R+1) vote: D gets the twin-A version first, then the
        // native vote too, so D can still process the others' later blocks that reference it.
        // Everyone else gets the native vote now and the twin-A version only after
        // `hide_delay`, once slot R is decided, so that D's later blocks (which reference the
        // twin-A versions) become processable and the DAG heals.
        if block.author() == Authority::from(sender) && block.round() == self.attack_round + 1 {
            let twin_a_vote = self.to_twin_a_vote(block);
            return if self.is_hidden(receiver) {
                (vec![NetworkMessage::Block(twin_a_vote), message], None)
            } else {
                (vec![message], Some(twin_a_vote))
            };
        }
        (vec![message], None)
    }
}

/// Holds back blocks whose round lies in `rounds` for `delay`; forwards everything else at once.
fn delayed(
    sender: mpsc::Sender<NetworkMessage>,
    delay: Duration,
    rounds: RangeInclusive<RoundNumber>,
) -> mpsc::Sender<NetworkMessage> {
    let (tx, mut rx) = mpsc::channel::<NetworkMessage>(16);
    SimulatorContext::spawn(async move {
        let mut queue: VecDeque<(Duration, NetworkMessage)> = VecDeque::new();
        let mut open = true;
        loop {
            let timer = queue
                .front()
                .map(|(at, _)| Sleep::new(at.saturating_sub(SimulatorContext::time())));
            tokio::select! {
                biased;
                _ = async { timer.expect("guarded").await }, if !queue.is_empty() => {
                    let (_, msg) = queue.pop_front().expect("non-empty");
                    if sender.send(msg).await.is_err() {
                        return;
                    }
                }
                msg = rx.recv(), if open => match msg {
                    Some(NetworkMessage::Block(b)) if rounds.contains(&b.round()) => {
                        queue.push_back((SimulatorContext::time() + delay, NetworkMessage::Block(b)));
                    }
                    Some(m) => {
                        if sender.send(m).await.is_err() {
                            return;
                        }
                    }
                    None => open = false,
                },
                else => return,
            }
        }
    });
    tx
}

/// Wrap the `from -> to` outbound channel with the fork attack behaviour.
///
/// `inbound` is the `to -> from` direction of the same link; L's twin A is reflected through it
/// into L's own DAG (once, on L's first link) so L can process the votes that reference it.
pub(crate) fn fork_attack_outbound(
    attacker: Arc<ForkAttacker>,
    from: usize,
    to: usize,
    sender: mpsc::Sender<NetworkMessage>,
    inbound: mpsc::Sender<NetworkMessage>,
) -> mpsc::Sender<NetworkMessage> {
    if attacker.should_delay(from, to) {
        let votes = attacker.attack_round + 1;
        return delayed(sender, attacker.hide_delay, votes..=votes);
    }
    if !attacker.is_equivocator(from) {
        return sender;
    }
    let (tx, mut rx) = mpsc::channel(16);
    let late = delayed(sender.clone(), attacker.hide_delay, 0..=RoundNumber::MAX);
    // The equivocator never sends to itself, so its own twin-A vote (referenced by D's later
    // blocks) is reflected into its own DAG through the first link, late like everyone else's.
    let late_self = delayed(inbound.clone(), attacker.hide_delay, 0..=RoundNumber::MAX);
    SimulatorContext::spawn(async move {
        while let Some(message) = rx.recv().await {
            if to == 1 && let Some(twin_a) = attacker.leader_twin_a(&message, from) {
                inbound.try_send(twin_a).ok();
            }
            let (now, later) = attacker.rewrite(message, from, to);
            for message in now {
                if sender.send(message).await.is_err() {
                    return;
                }
            }
            if let Some(block) = later {
                if to == 1 && late_self.send(NetworkMessage::Block(block.clone())).await.is_err() {
                    return;
                }
                if late.send(NetworkMessage::Block(block)).await.is_err() {
                    return;
                }
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attacker(e: usize) -> ForkAttacker {
        let config = ForkAttack {
            equivocators: e,
            hidden: 3,
            b_side: 3,
            attack_start_round: 10,
            hide_delay_ms: 5000,
        };
        ForkAttacker::new(&config, 14, LeaderElection::RoundRobin)
    }

    #[test]
    fn layout_and_attack_round() {
        // n=14, e=3: L=0, A'=1..6, B=6..9, D=9..12, E_rest=12..14; R=14.
        let a = attacker(3);
        assert_eq!(a.attack_round(), 14);
        assert!(a.is_equivocator(0) && a.is_equivocator(12) && a.is_equivocator(13));
        assert!(!a.is_equivocator(1) && !a.is_equivocator(11));
        assert_eq!(a.hidden, 9..12);
        assert_eq!(a.a_prime, 1..6);
        assert!(a.should_delay(9, 0) && a.should_delay(9, 13) && !a.should_delay(9, 10));
        assert!(!a.should_delay(1, 9));
    }

    #[test]
    fn flip_digest_is_an_involution() {
        let mut bytes = [0u8; BLOCK_DIGEST_SIZE];
        bytes[BLOCK_DIGEST_SIZE - 1] = 0xAB;
        let original = BlockDigest::from(bytes);
        let flipped = ForkAttacker::flip_digest(original);
        assert_ne!(original, flipped);
        assert_eq!(ForkAttacker::flip_digest(flipped), original);
    }
}
