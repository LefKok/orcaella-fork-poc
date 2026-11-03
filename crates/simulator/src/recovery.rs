// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork recovery over the fork-attack run (paper, Algorithm 2, "Fork Detection and Repair").
//!
//! Every correct replica watches its own DAG for fork evidence on the attacked slot `(L, R)`:
//! a VoteQC for one twin (`q` round-`R+1` blocks supporting it) together with a committed
//! later anchor whose causal history links `k` round-`R+1` blocks supporting the other twin (the
//! DAG form of a NewView that pins the other digest). On evidence it broadcasts an
//! `Alarm` stamped with its clock, halts, and waits `2Δ_sync`; on a valid `Alarm` it halts and
//! re-broadcasts. The lockstep rounds of the exchange are anchored to the earliest valid
//! `Alarm` timestamp, so correct replicas, whose clocks are synchronized to within the slack
//! in `Δ_sync`, share one round grid.
//!
//! At the end of the wait each replica fixes its input: the signed block headers of rounds
//! `R..=R+2` it holds (votes, twins, anchors) and its ChkProps, one per height from the height
//! below the attacked slot to its last commit. ChkProps are emulated as in
//! [`replica::result::ResilientOutcome`]: the state root at height `h` is the prefix hash of
//! the first `h` commits; a ChkProp also carries the root at `h-1`, which is how a root is
//! checked to extend the canonical branch. The inputs are exchanged with `n` parallel
//! Dolev-Strong broadcasts [DS83]: the sender signs its value and sends it in round 1; in
//! round `r` a replica relays every value it newly extracted in round `r-1`, after adding its
//! signature to the chain of `r-1` distinct ones; after `t+1` rounds, with `t = n-2f-c-1`,
//! an instance delivers its value if exactly one was extracted. Relays carry the full value,
//! as in the original protocol. Then every replica computes the exposed set `E` (two blocks
//! by one author in one round, or two ChkProps by one signer at one height), the highest
//! delivered CheckpointQC `C_max`, the canonical branch by the counting step, and signs the
//! new genesis; `q` matching signatures form the GenesisQC.
//!
//! Byzantine replicas take no part in detection, follow the exchange with the input the
//! adversary chooses (ChkProps for the root the hidden replicas committed, never for the
//! client-finalized one, which they gave to the client alone), and sign the genesis. Crashed
//! replicas stop at the `Alarm`. The replicas' normal-operation tasks keep running in the
//! background (the simulator cannot halt them without touching replica code): the halt is
//! modelled by the fixed inputs.
//!
//! [DS83]: D. Dolev and H. R. Strong, "Authenticated algorithms for Byzantine agreement",
//! SIAM Journal on Computing 12(4), 1983.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
    ops::Range,
    sync::{Arc, Mutex},
    time::Duration,
};

use dag::{
    authority::Authority,
    block::{Block, BlockReference, RoundNumber, data::Data},
    consensus::CommittedSubDag,
    context::Ctx,
    crypto::BlockDigest,
    storage::{BlockReader, CommitData},
};
use replica::result::{RecoveryReport, state_roots};
use tokio::{select, sync::mpsc};

use crate::{
    config::ForkAttack, context::SimulatorContext, executor::Sleep, network::SimulatedNetwork,
};

type Root = [u8; 32];

/// Bytes of a signature; a `(height, root, prev, signature)` ChkProp; the alarm's twins; the
/// genesis vote.
const SIGNATURE_BYTES: u64 = 64;
const CHKPROP_BYTES: u64 = 8 + 32 + 32 + SIGNATURE_BYTES;
const GENESIS_BYTES: u64 = 8 + 8 + SIGNATURE_BYTES;

/// Bytes of a signed block header: reference (8 + 8 + 32), parents, timestamp, signature.
fn header_bytes(block: &Block) -> u64 {
    48 + 48 * block.includes().len() as u64 + 8 + SIGNATURE_BYTES
}

/// How often a replica inspects its DAG for fork evidence.
const DETECTION_INTERVAL: Duration = Duration::from_millis(50);

/// Committee-level parameters of one recovery run.
pub(crate) struct RecoveryParams {
    pub n: usize,
    pub f: usize,
    pub c: usize,
    pub q: usize,
    pub k: usize,
    pub attack_round: RoundNumber,
    pub delta_sync: Duration,
    pub byzantine: Vec<bool>,
    pub crashed: Vec<bool>,
    pub hidden: Range<usize>,
}

impl RecoveryParams {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        attack: &ForkAttack,
        n: usize,
        f: usize,
        c: usize,
        q: usize,
        k: usize,
        attack_round: RoundNumber,
        delta_sync: Duration,
    ) -> Self {
        let mut byzantine = vec![false; n];
        for index in attack.equivocator_indices(n) {
            byzantine[index] = true;
        }
        let mut crashed = vec![false; n];
        for index in attack.crashed_indices(n) {
            crashed[index] = true;
        }
        Self {
            n,
            f,
            c,
            q,
            k,
            attack_round,
            delta_sync,
            byzantine,
            crashed,
            hidden: attack.hidden_indices(n),
        }
    }

    /// Dolev-Strong rounds: `t + 1` for `t = n - 2f - c - 1`.
    fn rounds(&self) -> usize {
        self.n - 2 * self.f - self.c
    }

    fn is_correct(&self, index: usize) -> bool {
        !self.byzantine[index] && !self.crashed[index]
    }

    fn leader(&self) -> Authority {
        Authority::from(0usize)
    }
}

/// One replica's ChkProp: its state root at `height` and the root it extends.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ChkProp {
    signer: usize,
    height: usize,
    root: Root,
    prev: Root,
}

/// One replica's broadcast input.
struct Input {
    signer: usize,
    headers: Vec<Data<Block>>,
    chkprops: Vec<ChkProp>,
}

impl Input {
    fn bytes(&self) -> u64 {
        8 + self.headers.iter().map(|b| header_bytes(b)).sum::<u64>()
            + CHKPROP_BYTES * self.chkprops.len() as u64
    }

    /// Identity of the value in the exchange (simulated hash).
    fn digest(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.signer.hash(&mut hasher);
        for block in &self.headers {
            block.reference().hash(&mut hasher);
        }
        self.chkprops.hash(&mut hasher);
        hasher.finish()
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Input(signer={}, headers={}, chkprops={})",
            self.signer,
            self.headers.len(),
            self.chkprops.len()
        )
    }
}

#[derive(Clone, Debug)]
enum Message {
    /// Fork evidence with the detector's clock reading.
    Alarm { at: Duration, bytes: u64 },
    /// A Dolev-Strong relay: the instance's value under `chain` signatures, the sender first.
    Relay {
        instance: usize,
        value: Arc<Input>,
        chain: Vec<usize>,
    },
    /// A signature on the new genesis, identified by its digest.
    Genesis { from: usize, digest: u64 },
}

/// What one replica computed after the exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Output {
    delivered: usize,
    exposed: BTreeSet<usize>,
    c_max: usize,
    /// ChkProp counts from non-exposed signers at the first height above `C_max`.
    first_counts: BTreeMap<Root, usize>,
    canonical: Vec<(usize, Root)>,
    break_height: Option<usize>,
    digest: u64,
}

#[derive(Default)]
struct Shared {
    commits: Vec<Vec<(Duration, CommitData)>>,
    detection: Option<Duration>,
    anchor: Option<Duration>,
    halted: Vec<Option<Duration>>,
    outputs: Vec<Option<Output>>,
    genesis: Vec<Option<Duration>>,
    input_bytes: Vec<u64>,
    sent_bytes: Vec<u64>,
    messages: Vec<u64>,
}

/// Handle on a running recovery; `report` reads the result at the end of the run.
pub(crate) struct Recovery {
    params: Arc<RecoveryParams>,
    shared: Arc<Mutex<Shared>>,
}

impl Recovery {
    /// Start the recovery tasks inside the simulated world. `commit_receivers[i]` streams
    /// replica `i`'s commits, `readers[i]` is its live block store.
    pub(crate) fn start(
        params: RecoveryParams,
        network: &SimulatedNetwork,
        readers: Vec<BlockReader>,
        commit_receivers: Vec<mpsc::Receiver<CommittedSubDag>>,
    ) -> Self {
        let n = params.n;
        let params = Arc::new(params);
        let shared = Arc::new(Mutex::new(Shared {
            commits: vec![Vec::new(); n],
            halted: vec![None; n],
            outputs: vec![None; n],
            genesis: vec![None; n],
            input_bytes: vec![0; n],
            sent_bytes: vec![0; n],
            messages: vec![0; n],
            ..Default::default()
        }));

        for (index, mut receiver) in commit_receivers.into_iter().enumerate() {
            let shared = shared.clone();
            SimulatorContext::spawn(async move {
                while let Some(sub_dag) = receiver.recv().await {
                    let commit = CommitData::from(&sub_dag);
                    shared.lock().expect("recovery state").commits[index]
                        .push((SimulatorContext::time(), commit));
                }
            });
        }

        // One latency link per ordered pair, merged into one inbox per replica.
        let mut inboxes = Vec::with_capacity(n);
        let mut outbound: Vec<Vec<Option<mpsc::Sender<Message>>>> = vec![vec![]; n];
        for to in 0..n {
            let (inbox_sender, inbox) = mpsc::channel::<Message>(1 << 16);
            inboxes.push(inbox);
            for (from, links) in outbound.iter_mut().enumerate() {
                if from == to {
                    links.push(None);
                    continue;
                }
                let (sender, mut receiver) =
                    SimulatedNetwork::latency_channel::<Message>(network.link(from, to));
                links.push(Some(sender));
                let inbox_sender = inbox_sender.clone();
                SimulatorContext::spawn(async move {
                    while let Some(message) = receiver.recv().await {
                        if inbox_sender.send(message).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }

        for (index, (inbox, peers)) in inboxes.into_iter().zip(outbound).enumerate() {
            let replica = Replica {
                index,
                params: params.clone(),
                shared: shared.clone(),
                reader: readers[index].clone(),
                peers,
                inbox,
                halted: None,
                anchor: None,
                input: None,
                extracted: vec![Vec::new(); n],
                pending: Vec::new(),
                sent_rounds: 0,
                output: None,
                genesis_votes: HashMap::new(),
                done: false,
            };
            SimulatorContext::spawn(replica.run());
        }

        Self { params, shared }
    }

    /// Summarize the recovery at the end of the run.
    pub(crate) fn report(&self) -> RecoveryReport {
        let params = &self.params;
        let shared = self.shared.lock().expect("recovery state");
        let ms = |d: Duration| d.as_millis() as u64;
        let correct: Vec<usize> = (0..params.n).filter(|&i| params.is_correct(i)).collect();

        let fork_height = shared.commits.iter().find_map(|stream| {
            stream.iter().position(|(_, commit)| {
                commit.leader.authority == params.leader()
                    && commit.leader.round == params.attack_round
            })
        });
        let root_at = |index: usize, height: usize| -> Option<Root> {
            let roots = state_roots(shared.commits[index].iter().map(|(_, c)| c.clone()));
            roots.get(height - 1).copied()
        };
        // The client-finalized root at the fork height is the one of the non-hidden honest
        // side (q - b honest attestations plus the b Byzantine ones given to the client).
        let finalized_root = fork_height.and_then(|position| {
            let height = position + 1;
            (1..params.hidden.start)
                .find(|&i| params.is_correct(i))
                .and_then(|i| root_at(i, height))
        });

        let outputs: Vec<&Output> = correct
            .iter()
            .filter_map(|&i| shared.outputs[i].as_ref())
            .collect();
        let reference = outputs.first().copied();
        let agreement = !outputs.is_empty()
            && outputs
                .iter()
                .all(|output| output.canonical == reference.expect("non-empty").canonical);

        let (count_finalized, count_conflicting) = match (reference, finalized_root) {
            (Some(output), Some(root)) => {
                let finalized = output.first_counts.get(&root).copied().unwrap_or(0);
                let conflicting = output
                    .first_counts
                    .iter()
                    .filter(|(r, _)| **r != root)
                    .map(|(_, count)| *count)
                    .max()
                    .unwrap_or(0);
                (finalized, conflicting)
            }
            _ => (0, 0),
        };
        let finalized_recovered = match (reference, finalized_root, fork_height) {
            (Some(output), Some(root), Some(position)) => Some(
                output
                    .canonical
                    .iter()
                    .any(|(height, r)| *height == position + 1 && *r == root),
            ),
            _ => None,
        };

        let genesis: Vec<Duration> = correct.iter().filter_map(|&i| shared.genesis[i]).collect();
        let genesis_first = genesis.iter().min().copied();
        let genesis_last = (genesis.len() == correct.len())
            .then(|| genesis.iter().max().copied())
            .flatten();
        let rounds = params.rounds();
        let exchange_start = shared.anchor.map(|anchor| anchor + 2 * params.delta_sync);
        let exchange_end = exchange_start.map(|start| start + params.delta_sync * rounds as u32);

        RecoveryReport {
            delta_sync_ms: ms(params.delta_sync),
            rounds,
            correct: correct.len(),
            detection_ms: shared.detection.map(ms),
            alarm_ms: shared.anchor.map(ms),
            exchange_start_ms: exchange_start.map(ms),
            exchange_end_ms: exchange_end.map(ms),
            genesis_first_ms: genesis_first.map(ms),
            genesis_last_ms: genesis_last.map(ms),
            recovery_ms: match (shared.anchor, genesis_last) {
                (Some(anchor), Some(last)) => Some(ms(last - anchor)),
                _ => None,
            },
            fork_height: fork_height.map(|position| position + 1),
            c_max: reference.map_or(0, |output| output.c_max),
            exposed: reference.map_or(0, |output| output.exposed.len()),
            exposed_only_byzantine: reference
                .is_some_and(|output| output.exposed.iter().all(|&i| params.byzantine[i])),
            count_finalized,
            count_conflicting,
            finalized_recovered,
            break_height: reference.and_then(|output| output.break_height),
            agreement,
            canonical_height: reference
                .and_then(|output| output.canonical.last().map(|(height, _)| *height))
                .unwrap_or(0),
            input_bytes_max: correct
                .iter()
                .map(|&i| shared.input_bytes[i])
                .max()
                .unwrap_or(0),
            sent_bytes_max: correct
                .iter()
                .map(|&i| shared.sent_bytes[i])
                .max()
                .unwrap_or(0),
            sent_bytes_total: shared.sent_bytes.iter().sum(),
            messages_total: shared.messages.iter().sum(),
        }
    }
}

struct Replica {
    index: usize,
    params: Arc<RecoveryParams>,
    shared: Arc<Mutex<Shared>>,
    reader: BlockReader,
    peers: Vec<Option<mpsc::Sender<Message>>>,
    inbox: mpsc::Receiver<Message>,
    /// When this replica halted normal operation.
    halted: Option<Duration>,
    /// Earliest valid Alarm timestamp seen: the anchor of the round grid.
    anchor: Option<Duration>,
    input: Option<Arc<Input>>,
    /// Per instance, the values extracted so far (at most two are kept).
    extracted: Vec<Vec<(u64, Arc<Input>)>>,
    /// Relays to send at the next round boundary.
    pending: Vec<(usize, Arc<Input>, Vec<usize>)>,
    /// Rounds whose messages were sent.
    sent_rounds: usize,
    output: Option<Output>,
    genesis_votes: HashMap<u64, HashSet<usize>>,
    done: bool,
}

impl Replica {
    async fn run(mut self) {
        let crashed = self.params.crashed[self.index];
        let detects = !self.params.byzantine[self.index];
        loop {
            let now = SimulatorContext::time();
            let deadline = match (self.halted, self.anchor) {
                (None, _) if detects => Some(now + DETECTION_INTERVAL),
                (None, _) => None,
                (Some(_), Some(anchor)) => self.next_boundary(anchor),
                (Some(_), None) => None,
            };
            let timer = deadline.map(|at| Sleep::new(at.saturating_sub(now)));
            select! {
                biased;
                _ = async { timer.expect("guarded").await }, if deadline.is_some() => {
                    if self.halted.is_none() {
                        self.detect().await;
                        if crashed && self.halted.is_some() {
                            return;
                        }
                    } else {
                        self.on_boundary().await;
                    }
                }
                message = self.inbox.recv() => {
                    let Some(message) = message else { return };
                    self.on_message(message).await;
                    if crashed && self.halted.is_some() {
                        return;
                    }
                }
            }
        }
    }

    /// Round `r` of the exchange spans `[S + (r-1)Δ, S + rΔ)` with `S = anchor + 2Δ`.
    fn exchange_start(&self, anchor: Duration) -> Duration {
        anchor + 2 * self.params.delta_sync
    }

    fn next_boundary(&self, anchor: Duration) -> Option<Duration> {
        if self.done {
            return None;
        }
        let start = self.exchange_start(anchor);
        Some(start + self.params.delta_sync * self.sent_rounds as u32)
    }

    async fn broadcast(&mut self, message: Message, bytes: u64) {
        for peer in self.peers.iter().flatten() {
            peer.send(message.clone()).await.ok();
        }
        let mut shared = self.shared.lock().expect("recovery state");
        shared.sent_bytes[self.index] += bytes * (self.params.n as u64 - 1);
        shared.messages[self.index] += self.params.n as u64 - 1;
    }

    /// Look for fork evidence on slot `(L, R)` in the local DAG.
    async fn detect(&mut self) {
        let params = self.params.clone();
        let round = params.attack_round;
        if self.reader.highest_round() < round + 2 {
            return;
        }
        let votes = self.reader.get_blocks_by_round(round + 1);
        let mut support: HashMap<BlockDigest, Vec<Data<Block>>> = HashMap::new();
        for block in &votes {
            if let Some(twin) = supported_twin(block, params.leader(), round) {
                support.entry(twin).or_default().push(block.clone());
            }
        }
        let Some((_, voteqc)) = support
            .iter()
            .find(|(_, blocks)| distinct_authors(blocks.iter().map(|b| &**b)) >= params.q)
        else {
            return;
        };
        let voteqc_twin = voteqc[0]
            .includes()
            .iter()
            .find(|r| r.author_round() == (params.leader(), round))
            .map(|r| r.digest);
        let anchors: Vec<BlockReference> = {
            let shared = self.shared.lock().expect("recovery state");
            shared.commits[self.index]
                .iter()
                .map(|(_, commit)| commit.leader)
                .filter(|leader| leader.round >= round + 2)
                .collect()
        };
        for (twin, blocks) in &support {
            if Some(*twin) == voteqc_twin
                || distinct_authors(blocks.iter().map(|b| &**b)) < params.k
            {
                continue;
            }
            for anchor in &anchors {
                let Some(anchor_block) = self.reader.get_block(*anchor) else {
                    continue;
                };
                let linked = blocks
                    .iter()
                    .filter(|block| self.reader.linked(&anchor_block, block))
                    .map(|b| &**b);
                if distinct_authors(linked) >= params.k {
                    let twins = self
                        .reader
                        .get_blocks_at_authority_round(params.leader(), round);
                    let bytes = twins
                        .iter()
                        .chain(votes.iter())
                        .map(|b| header_bytes(b))
                        .sum::<u64>()
                        + header_bytes(&anchor_block);
                    let now = SimulatorContext::time();
                    tracing::info!(
                        "Replica {} detected the fork on slot ({}, {}) at {now:?}",
                        self.index,
                        params.leader(),
                        round
                    );
                    {
                        let mut shared = self.shared.lock().expect("recovery state");
                        shared.detection.get_or_insert(now);
                        shared.halted[self.index] = Some(now);
                    }
                    self.halted = Some(now);
                    self.adopt_anchor(now);
                    self.broadcast(Message::Alarm { at: now, bytes }, bytes)
                        .await;
                    return;
                }
            }
        }
    }

    fn adopt_anchor(&mut self, at: Duration) {
        if self.anchor.is_none_or(|anchor| at < anchor) {
            self.anchor = Some(at);
            let mut shared = self.shared.lock().expect("recovery state");
            if shared.anchor.is_none_or(|anchor| at < anchor) {
                shared.anchor = Some(at);
            }
        }
    }

    async fn on_message(&mut self, message: Message) {
        let now = SimulatorContext::time();
        match message {
            Message::Alarm { at, bytes } => {
                // Valid if not from the future and at most one re-broadcast hop old.
                if at > now || now - at > 2 * self.params.delta_sync {
                    return;
                }
                if self.halted.is_none() {
                    self.halted = Some(now);
                    self.shared.lock().expect("recovery state").halted[self.index] = Some(now);
                    self.adopt_anchor(at);
                    if !self.params.crashed[self.index] {
                        self.broadcast(Message::Alarm { at, bytes }, bytes).await;
                    }
                } else if self.input.is_none() {
                    self.adopt_anchor(at);
                }
            }
            Message::Relay {
                instance,
                value,
                chain,
            } => self.on_relay(instance, value, chain, now),
            Message::Genesis { from, digest } => {
                let votes = self.genesis_votes.entry(digest).or_default();
                votes.insert(from);
                self.check_genesis_qc(now);
            }
        }
    }

    fn on_relay(&mut self, instance: usize, value: Arc<Input>, chain: Vec<usize>, now: Duration) {
        let Some(anchor) = self.anchor else { return };
        let start = self.exchange_start(anchor);
        if now < start {
            return;
        }
        let rounds = self.params.rounds();
        let local_round =
            ((now - start).as_nanos() / self.params.delta_sync.as_nanos()) as usize + 1;
        let valid = chain.len() == local_round
            && local_round <= rounds
            && chain.first() == Some(&instance)
            && chain.iter().collect::<HashSet<_>>().len() == chain.len()
            && !chain.contains(&self.index)
            && chain.iter().all(|&s| s < self.params.n)
            && value.signer == instance;
        if !valid {
            return;
        }
        let digest = value.digest();
        let extracted = &mut self.extracted[instance];
        if extracted.len() >= 2 || extracted.iter().any(|(d, _)| *d == digest) {
            return;
        }
        extracted.push((digest, value.clone()));
        if local_round < rounds {
            let mut chain = chain;
            chain.push(self.index);
            self.pending.push((instance, value, chain));
        }
    }

    /// A round boundary: fix the input at the start of the exchange, send the pending relays
    /// of the round that begins, or finish after the last round.
    async fn on_boundary(&mut self) {
        let rounds = self.params.rounds();
        if self.sent_rounds == 0 {
            let input = Arc::new(self.fix_input());
            self.shared.lock().expect("recovery state").input_bytes[self.index] = input.bytes();
            self.extracted[self.index].push((input.digest(), input.clone()));
            self.pending
                .push((self.index, input.clone(), vec![self.index]));
            self.input = Some(input);
        }
        if self.sent_rounds == rounds {
            self.finish().await;
            return;
        }
        self.sent_rounds += 1;
        let pending = std::mem::take(&mut self.pending);
        for (instance, value, chain) in pending {
            let bytes = value.bytes() + (SIGNATURE_BYTES + 8) * chain.len() as u64 + 16;
            self.broadcast(
                Message::Relay {
                    instance,
                    value,
                    chain,
                },
                bytes,
            )
            .await;
        }
    }

    /// The input at the end of the `2Δ_sync` wait: headers of rounds `R..=R+2` held now, and
    /// ChkProps from the height below the attacked slot up to the last commit at the end of the wait.
    fn fix_input(&self) -> Input {
        let params = &self.params;
        let round = params.attack_round;
        let headers: Vec<Data<Block>> = (round..=round + 2)
            .flat_map(|r| self.reader.get_blocks_by_round(r))
            .collect();
        let shared = self.shared.lock().expect("recovery state");
        let halted = self.halted.expect("input is fixed after the halt");
        let fork_position = shared.commits.iter().find_map(|stream| {
            stream.iter().position(|(_, commit)| {
                commit.leader.authority == params.leader() && commit.leader.round == round
            })
        });
        // Byzantine replicas attest the roots of the hidden side, which committed the other
        // twin; everyone else attests its own commits.
        let source = if params.byzantine[self.index] {
            params.hidden.start
        } else {
            self.index
        };
        // The wait lets a replica finish processing the blocks already sent to it, so its
        // commits up to the end of the wait count (the simulator cannot stop the replicas'
        // normal-operation tasks, so a few heights above the attacked slot may use blocks
        // sent after the halt; they do not affect the count at the forked height).
        let fixed = self
            .anchor
            .map_or(halted, |anchor| self.exchange_start(anchor));
        let commits: Vec<CommitData> = shared.commits[source]
            .iter()
            .take_while(|(at, _)| *at <= fixed)
            .map(|(_, commit)| commit.clone())
            .collect();
        let roots = state_roots(commits);
        let first = fork_position.unwrap_or(roots.len().saturating_sub(1));
        let chkprops = (first.max(1)..=roots.len())
            .map(|height| ChkProp {
                signer: self.index,
                height,
                root: roots[height - 1],
                prev: if height >= 2 {
                    roots[height - 2]
                } else {
                    [0; 32]
                },
            })
            .collect();
        Input {
            signer: self.index,
            headers,
            chkprops,
        }
    }

    /// Deliver the instances with exactly one extracted value, expose, count, sign the genesis.
    async fn finish(&mut self) {
        self.done = true;
        let params = self.params.clone();
        let delivered: Vec<Arc<Input>> = self
            .extracted
            .iter()
            .filter(|values| values.len() == 1)
            .map(|values| values[0].1.clone())
            .collect();

        let mut exposed = BTreeSet::new();
        let mut by_slot: HashMap<(Authority, RoundNumber), HashSet<BlockDigest>> = HashMap::new();
        let mut by_height: HashMap<(usize, usize), HashSet<Root>> = HashMap::new();
        let mut chkprops: BTreeMap<usize, Vec<&ChkProp>> = BTreeMap::new();
        for input in &delivered {
            for block in &input.headers {
                by_slot
                    .entry(block.author_round())
                    .or_default()
                    .insert(block.digest());
            }
            for chkprop in &input.chkprops {
                by_height
                    .entry((chkprop.signer, chkprop.height))
                    .or_default()
                    .insert(chkprop.root);
                chkprops.entry(chkprop.height).or_default().push(chkprop);
            }
        }
        for ((author, _), digests) in &by_slot {
            if digests.len() >= 2 {
                exposed.insert(author.index());
            }
        }
        for ((signer, _), roots) in &by_height {
            if roots.len() >= 2 {
                exposed.insert(*signer);
            }
        }

        // C_max: the highest height at which one root carries q ChkProps (a CheckpointQC).
        let mut c_max = None;
        for (height, props) in chkprops.iter().rev() {
            let mut signers: HashMap<Root, HashSet<usize>> = HashMap::new();
            for prop in props {
                signers.entry(prop.root).or_default().insert(prop.signer);
            }
            if let Some((root, _)) = signers.iter().find(|(_, s)| s.len() >= params.q) {
                c_max = Some((*height, *root));
                break;
            }
        }
        let mut canonical: Vec<(usize, Root)> = c_max.into_iter().collect();
        let (mut height, mut last_root) = c_max.map_or((1, [0; 32]), |(h, r)| (h + 1, r));
        let mut first_counts = BTreeMap::new();
        let mut break_height = None;
        while let Some(props) = chkprops.get(&height) {
            let mut counts: BTreeMap<Root, HashSet<usize>> = BTreeMap::new();
            let mut prev: HashMap<Root, Root> = HashMap::new();
            for prop in props.iter().filter(|p| !exposed.contains(&p.signer)) {
                counts.entry(prop.root).or_default().insert(prop.signer);
                prev.insert(prop.root, prop.prev);
            }
            let counts: BTreeMap<Root, usize> =
                counts.into_iter().map(|(r, s)| (r, s.len())).collect();
            if first_counts.is_empty() {
                first_counts = counts.clone();
            }
            let best = counts.values().max().copied().unwrap_or(0);
            let winners: Vec<Root> = counts
                .iter()
                .filter(|(_, c)| **c == best)
                .map(|(r, _)| *r)
                .collect();
            let extends = |root: &Root| (c_max.is_none() && height == 1) || prev[root] == last_root;
            match winners.as_slice() {
                [root] if best > 0 && extends(root) => {
                    canonical.push((height, *root));
                    last_root = *root;
                    height += 1;
                }
                _ => {
                    break_height = Some(height);
                    break;
                }
            }
        }
        // Beyond the counting step, Algorithm 2 extends per slot with the lowest-digest
        // delivered VoteQC: at the attacked slot that is the twin with q delivered supports.
        if let Some(stop) = break_height {
            let mut support: HashMap<BlockDigest, HashSet<Authority>> = HashMap::new();
            for input in &delivered {
                for block in &input.headers {
                    if block.round() == params.attack_round + 1
                        && let Some(twin) =
                            supported_twin(block, params.leader(), params.attack_round)
                    {
                        support.entry(twin).or_default().insert(block.author());
                    }
                }
            }
            let voteqc = support
                .iter()
                .filter(|(_, s)| s.len() >= params.q)
                .map(|(d, _)| *d)
                .min();
            let shared = self.shared.lock().expect("recovery state");
            let fork_position = shared.commits.iter().find_map(|stream| {
                stream.iter().position(|(_, commit)| {
                    commit.leader.author_round() == (params.leader(), params.attack_round)
                })
            });
            if let (Some(twin), Some(position)) = (voteqc, fork_position)
                && stop == position + 1
            {
                // The root a replica that committed this twin holds at that height.
                let root = shared.commits.iter().find_map(|stream| {
                    (stream.get(position)?.1.leader.digest == twin).then(|| {
                        state_roots(stream.iter().take(position + 1).map(|(_, c)| c.clone()))
                            .last()
                            .copied()
                    })?
                });
                if let Some(root) = root {
                    canonical.push((stop, root));
                }
            }
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        canonical.hash(&mut hasher);
        let digest = hasher.finish();
        let output = Output {
            delivered: delivered.len(),
            exposed,
            c_max: c_max.map_or(0, |(h, _)| h),
            first_counts,
            canonical,
            break_height,
            digest,
        };
        tracing::info!(
            "Replica {} finished the exchange: delivered={} exposed={:?} c_max={} break={:?} canonical_height={}",
            self.index,
            output.delivered,
            output.exposed,
            output.c_max,
            output.break_height,
            output.canonical.last().map_or(0, |(h, _)| *h)
        );
        self.shared.lock().expect("recovery state").outputs[self.index] = Some(output.clone());
        self.output = Some(output);
        self.genesis_votes
            .entry(digest)
            .or_default()
            .insert(self.index);
        self.broadcast(
            Message::Genesis {
                from: self.index,
                digest,
            },
            GENESIS_BYTES,
        )
        .await;
        self.check_genesis_qc(SimulatorContext::time());
    }

    fn check_genesis_qc(&mut self, now: Duration) {
        let Some(output) = &self.output else { return };
        let votes = self
            .genesis_votes
            .get(&output.digest)
            .map_or(0, HashSet::len);
        if votes >= self.params.q {
            let mut shared = self.shared.lock().expect("recovery state");
            shared.genesis[self.index].get_or_insert(now);
        }
    }
}

/// The twin of `(leader, round)` that `block` supports: its first reference to that slot.
fn supported_twin(block: &Block, leader: Authority, round: RoundNumber) -> Option<BlockDigest> {
    block
        .includes()
        .iter()
        .find(|r| r.author_round() == (leader, round))
        .map(|r| r.digest)
}

fn distinct_authors<'a>(blocks: impl IntoIterator<Item = &'a Block>) -> usize {
    blocks
        .into_iter()
        .map(Block::author)
        .collect::<HashSet<_>>()
        .len()
}
