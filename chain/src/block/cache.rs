//! Block tree implementation with generic storage backend.
//!
//! *Handles block import, chain selection, difficulty calculation and block storage.*
//!
#![warn(missing_docs)]

#[cfg(test)]
pub mod test;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::ControlFlow;
use log::error;

use nakamoto_common::bitcoin::blockdata::block::BlockHeader;
use nakamoto_common::bitcoin::hash_types::BlockHash;
use nakamoto_common::bitcoin::util::BitArray;
use nakamoto_common::bitcoin::Error::{BlockBadProofOfWork, BlockBadTarget};

use nakamoto_common::bitcoin::util::uint::Uint256;
use nakamoto_common::bitcoin_hashes::hex::ToHex;
use nakamoto_common::block::tree::{self, BlockReader, BlockTree, Branch, Error, ImportResult};
use nakamoto_common::block::{self, iter::Iter, store::Store, time::{self, Clock}, Bits, BlockTime, Height, Work, Target};
use nakamoto_common::network::Network;
use nakamoto_common::nonempty::NonEmpty;
use nakamoto_common::params::Params;

/// A block that is being stored by the block cache.
#[derive(Debug, Clone, Copy)]
struct CachedBlock {
    pub height: Height,
    pub header: BlockHeader,
}

impl CachedBlock {
    fn hash(&self) -> BlockHash {
        self.header.block_hash()
    }
}

impl std::ops::Deref for CachedBlock {
    type Target = BlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl tree::Header for CachedBlock {
    fn work(&self) -> Work {
        self.header.work()
    }
}

/// A chain candidate, forking off the active chain.
#[derive(Debug)]
struct Candidate {
    tip: BlockHash,
    headers: Vec<BlockHeader>,
    fork_height: Height,
    fork_header: BlockHeader,
}

/// An implementation of [`BlockTree`] using a generic storage backend.
/// Most of the functionality is accessible via the trait.
#[derive(Debug, Clone)]
pub struct BlockCache<S: Store> {
    chain: NonEmpty<CachedBlock>,
    headers: HashMap<BlockHash, Height>,
    orphans: HashMap<BlockHash, BlockHeader>,
    checkpoints: BTreeMap<Height, BlockHash>,
    params: Params,
    /// Total cumulative work on the active chain.
    chainwork: Uint256,
    store: S,
}

impl<S: Store<Header=BlockHeader>> BlockCache<S> {
    /// Create a new `BlockCache` from a `Store`, consensus parameters, and checkpoints.
    pub fn new(
        store: S,
        params: Params,
        checkpoints: &[(Height, BlockHash)],
    ) -> Result<Self, Error> {
        let genesis = store.genesis();
        let length = store.len()?;
        let orphans = HashMap::new();
        let checkpoints = checkpoints.iter().cloned().collect();
        let chainwork = genesis.work();
        let chain = NonEmpty::from((
            CachedBlock {
                height: 0,
                header: genesis,
            },
            Vec::with_capacity(length - 1),
        ));
        let mut headers = HashMap::with_capacity(length);
        // Insert genesis in the headers map, but skip it during iteration.
        headers.insert(chain.head.hash(), 0);

        Ok(Self {
            chain,
            headers,
            orphans,
            params,
            checkpoints,
            chainwork,
            store,
        })
    }

    /// Create a new `BlockCache` from a `Store`, consensus parameters, and checkpoints,
    /// and load all the blocks from the store.
    pub fn from(
        store: S,
        params: Params,
        checkpoints: &[(Height, BlockHash)],
    ) -> Result<Self, Error> {
        Self::new(store, params, checkpoints)?.load()
    }

    /// Load the block headers from the store, into the cache.
    pub fn load(self) -> Result<Self, Error> {
        self.load_with(|_| ControlFlow::Continue(()))
    }

    /// Load the block headers from the store, into the cache.
    /// Takes a function that is called for each block imported.
    pub fn load_with(
        mut self,
        progress: impl Fn(Height) -> ControlFlow<()>,
    ) -> Result<Self, Error> {
        for result in self.store.iter().skip(1) {
            let (height, header) = result?;

            self.chain.push(CachedBlock { height, header });
            self.chainwork = self.chainwork + header.work();

            if progress(height).is_break() {
                return Err(Error::Interrupted);
            }
        }

        // Make sure that the store was properly configured. If we loaded a store that doesn't
        // match the provided genesis, we return an error here.
        if let Some(header) = self.chain.tail.first() {
            let genesis = self.store.genesis().block_hash();
            println!("genesis {genesis}");
            if genesis != header.prev_blockhash {
                println!("header {:?}", header);

                println!("header.prev_blockhash {}", header.prev_blockhash);

                return Err(Error::GenesisMismatch);
            }
            if self.params.network.genesis_hash() != genesis {
                return Err(Error::GenesisMismatch);
            }
        }

        // Build header index.
        for cb in self.chain.tail.iter() {
            self.headers.insert(cb.prev_blockhash, cb.height - 1);
        }
        self.headers.insert(self.chain.last().hash(), self.height());

        let length = self.store.len()?;
        assert_eq!(length, self.chain.len());
        assert_eq!(length, self.headers.len());

        Ok(self)
    }

    /// Iterate over a range of blocks.
    ///
    /// # Errors
    ///
    /// Panics if the range is negative.
    ///
    fn range(&self, range: std::ops::Range<Height>) -> impl Iterator<Item=&CachedBlock> + '_ {
        assert!(
            range.start <= range.end,
            "BlockCache::range: range start must not be greater than range end"
        );

        self.chain
            .iter()
            .skip(range.start as usize)
            .take((range.end - range.start) as usize)
    }

    /// Get the median time past for the blocks leading up to the given height.
    ///
    /// # Errors
    ///
    /// Panics if height is `0`.
    ///
    pub fn median_time_past(&self, height: Height) -> BlockTime {
        assert!(height != 0, "height must be > 0");

        let mut times = [0; time::MEDIAN_TIME_SPAN as usize];

        let start = height.saturating_sub(time::MEDIAN_TIME_SPAN);
        let end = height;

        for (i, blk) in self.range(start..end).enumerate() {
            times[i] = blk.time;
        }

        // Gracefully handle the case where `height` < `MEDIUM_TIME_SPAN`.
        let available = &mut times[0..(end - start) as usize];

        available.sort_unstable();
        available[available.len() / 2]
    }

    /// Import a block into the tree. Performs header validation. This function may trigger
    /// a chain re-org.
    fn import_block(
        &mut self,
        header: BlockHeader,
        clock: &impl Clock,
    ) -> Result<ImportResult, Error> {
        let hash = header.block_hash();
        let tip = self.chain.last();
        let best = tip.hash();

        if self.headers.contains_key(&hash) || self.orphans.contains_key(&hash) {
            return Err(Error::DuplicateBlock(hash));
        }

        // Block extends the active chain. We can fully validate it before proceeding.
        // Instead of adding the block to the main chain, we let chain selection do the job.
        if header.prev_blockhash == best {
            self.validate(tip, &header, clock)?;
        }

        // Validate that the block's PoW is valid against its difficulty target, and
        // is greater than the minimum allowed for this network.
        //
        // We do this because it's cheap to verify and prevents flooding attacks.
        let target = header.target();
        let limit = self.params.pow_limit;
        match self.params.network {
            Network::Mainnet | Network::Testnet | Network::Regtest | Network::Signet => {
                match header.validate_pow(&target) {
                    Ok(_) => {
                        let limit = self.params.pow_limit;
                        if target > limit {
                            return Err(Error::InvalidBlockTarget(target, limit));
                        }
                    }
                    Err(BlockBadProofOfWork) => {
                        return Err(Error::InvalidBlockPoW);
                    }
                    Err(BlockBadTarget) => unreachable! {
                        // The only way to get a 'bad target' error is to pass a different target
                        // than the one specified in the header.
                    },
                    Err(_) => unreachable! {
                        // We've handled all possible errors above.
                    },
                }
            }
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET | Network::DOGECOINREGTEST => {
                if target > limit {
                    println!("target {}", target);
                    println!("limit {}", limit);
                    return Err(Error::InvalidBlockTarget(target, limit));
                }
            }
        }

        if let Some(height) = self.headers.get(&header.prev_blockhash) {
            // Don't accept any forks from the main chain, prior to the last checkpoint.
            if *height < self.last_checkpoint() {
                return Err(Error::InvalidBlockHeight(*height + 1));
            }
        }
        // We can now insert the header in the orphan set for further processing.
        self.orphans.insert(hash, header);

        // If it doesn't connect to any existing block, there's nothing left to do.
        // We know for a fact we won't discover any new branches.
        if !self.orphans.contains_key(&header.prev_blockhash)
            && !self.headers.contains_key(&header.prev_blockhash)
        {
            return Err(Error::BlockMissing(header.prev_blockhash));
        }

        // Find the best fork.
        //
        // Note that we can't compare candidates with each other directly, as they may have
        // different fork heights. So a candidate with less work than another may infact result
        // in a longer chain if selected, due to replacing less blocks on the active chain.
        let candidates = self.chain_candidates(clock);
        if candidates.is_empty() {
            return Ok(ImportResult::TipUnchanged);
        }

        let mut best_branch = None;
        let mut best_hash = tip.hash();
        let mut best_work = Uint256::zero();

        for branch in candidates.iter() {
            // Total work included in this branch.
            let candidate_work = Branch(&branch.headers).work();
            // Work included on the active chain that would be lost if we switched to the candidate
            // branch.
            let lost_work = Branch(self.chain_suffix(branch.fork_height)).work();
            // Not interested in candidates that result in a shorter chain.
            if candidate_work < lost_work {
                continue;
            }
            // Work added onto the main chain if this candidate were selected.
            let added = candidate_work - lost_work;
            if added > best_work {
                best_branch = Some(branch);
                best_work = added;
                best_hash = branch.tip;
            } else if self.params.network != Network::Mainnet
                && self.params.network != Network::DOGECOINMAINNET
            {
                if added == best_work {
                    // Nb. We intend here to compare the hashes as integers, and pick the lowest
                    // hash as the winner. However, the `PartialEq` on `BlockHash` is implemented on
                    // the underlying `[u8]` array, and does something different (lexographical
                    // comparison). Since this code isn't run on Mainnet, it's okay, as it serves
                    // its purpose of being determinstic when choosing the active chain.
                    if branch.tip < best_hash {
                        best_branch = Some(branch);
                        best_hash = branch.tip;
                    }
                }
            }
        }

        {
            // Prune orphans.
            let hashes = self
                .orphans
                .keys()
                .filter(|h| self.contains(h))
                .cloned()
                .collect::<Vec<_>>();

            for h in hashes {
                self.orphans.remove(&h);
            }
        }

        if let Some(branch) = best_branch {
            // Stale blocks after potential re-org.
            let reverted = self.switch_to_fork(branch)?;
            let height = self.height();
            let hash = branch.tip;
            let header = *branch
                .headers
                .last()
                .expect("BlockCache::import_block: fork candidates cannot be empty");
            let start = branch.fork_height + 1;
            let end = height + 1;

            assert!(end > start);

            let connected = NonEmpty::from_vec(
                self.range(start..end)
                    .map(|b| (b.height, b.header))
                    .collect(),
            )
                .expect("BlockCache::import_block: there is always at least one connected block");

            Ok(ImportResult::TipChanged {
                header,
                hash,
                height,
                reverted,
                connected,
            })
        } else {
            Ok(ImportResult::TipUnchanged)
        }
    }

    /// Find all the potential forks off the main chain.
    fn chain_candidates(&self, clock: &impl Clock) -> Vec<Candidate> {
        let mut branches = Vec::new();

        for tip in self.orphans.keys() {
            if let Some(branch) = self.fork(tip) {
                if self.validate_branch(&branch, clock).is_ok() {
                    branches.push(branch);
                }
            }
        }
        branches
    }

    /// Find a potential branch starting from the active chain and ending at the given tip.
    /// The tip must not be an active block. Returns `None` if no branch was found.
    ///
    /// # Errors
    ///
    /// Panics if the provided tip is on the active chain.
    ///
    fn fork(&self, tip: &BlockHash) -> Option<Candidate> {
        let tip = *tip;

        let mut headers = VecDeque::new();
        let mut cursor = tip;

        assert!(
            !self.headers.contains_key(&tip),
            "BlockCache::fork: the provided tip must not be on the active chain"
        );

        while let Some(header) = self.orphans.get(&cursor) {
            cursor = header.prev_blockhash;
            headers.push_front(*header);
        }

        if let Some((fork_height, fork_header)) = self.get_block(&cursor) {
            assert!(!headers.is_empty());

            return Some(Candidate {
                tip,
                fork_height,
                fork_header: *fork_header,
                headers: headers.into(),
            });
        }
        None
    }

    /// Validate a candidate branch. This function is useful for chain selection.
    fn validate_branch(&self, candidate: &Candidate, clock: &impl Clock) -> Result<(), Error> {
        let mut tip = CachedBlock {
            height: candidate.fork_height,
            header: candidate.fork_header,
        };

        for header in candidate.headers.iter() {
            self.validate(&tip, header, clock)?;

            tip = CachedBlock {
                height: tip.height + 1,
                header: *header,
            };
        }
        Ok(())
    }

    // fn doge_compact_target(&self,tip: &CachedBlock, header: &BlockHeader) -> Bits {
    //     let proof_of_work_limit = block::pow_limit_bits(&self.params.network);
    //
    // }
    //
    fn allow_digishield_min_difficulty_for_block(&self, tip: &CachedBlock, header: &BlockHeader) -> bool {
        if !self.params.doge_allow_min_difficulty_blocks(tip.height) {
            return false;
        }

        if tip.height < 157500 {
            return false;
        }

        header.time > (tip.time + self.params.doge_pow_target_timespan(tip.height) as BlockTime * 2)
    }

    fn calculate_doge_compact_target(&self, tip: &CachedBlock, header: &BlockHeader) -> Bits {
        let proof_of_work_limit = block::pow_limit_bits(&self.params.network);
        // println!("proof_of_work_limit {}",proof_of_work_limit.to_hex());
        if self.allow_digishield_min_difficulty_for_block(tip, header) {
            return proof_of_work_limit;
        }

        let difficulty_adjustment_interval = if tip.height >= 145000 {
            1
        } else {
            self.params.doge_pow_target_timespan(tip.height) / self.params.pow_target_spacing
        };

        if (tip.height + 1) % difficulty_adjustment_interval != 0 {
            if self.params.doge_allow_min_difficulty_blocks(tip.height) {
                // Special difficulty rule for testnet:
                // If the new block's timestamp is more than 2* 10 minutes
                // then allow mining of a min-difficulty block.
                if header.time > tip.time + self.params.pow_target_spacing as BlockTime * 2 {
                    return proof_of_work_limit;
                } else {
                    // Return the last non-special-min-difficulty-rules-block
                    return self.doge_next_min_difficulty_target(&self.params, tip.height, difficulty_adjustment_interval);
                }
            }
            tip.bits
        } else {
            // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
            // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
            let mut blocks_to_go_back = difficulty_adjustment_interval - 1;
            if tip.height + 1 != difficulty_adjustment_interval {
                blocks_to_go_back = difficulty_adjustment_interval
            }

            // Go back by what we want to be 14 days worth of blocks
            let height_first = tip.height - blocks_to_go_back;
            let first = self.get_block_by_height(height_first).unwrap();
            self.calculate_dogecoin_next_work_required(tip, first.time)
        }
    }

    fn calculate_dogecoin_next_work_required(&self, pindex_last: &CachedBlock, n_first_block_time: BlockTime) -> Bits {
        let n_height = pindex_last.height + 1;
        let retarget_timespan = self.params.doge_pow_target_timespan(n_height) as i64;
        let n_actual_timespan = pindex_last.time as i64 - n_first_block_time as i64;
        let mut n_modulated_timespan = n_actual_timespan;
        let n_min_timespan;
        let n_max_timespan;
        if self.params.doge_digishield_difficulty_calculation(n_height) {
            // DigiShield implementation
            n_modulated_timespan = retarget_timespan + (n_modulated_timespan - retarget_timespan) / 8;

            n_min_timespan = retarget_timespan - (retarget_timespan / 4);
            n_max_timespan = retarget_timespan + (retarget_timespan / 2);
        } else if n_height > 10000 {
            n_min_timespan = retarget_timespan / 4;
            n_max_timespan = retarget_timespan * 4;
        } else if n_height > 5000 {
            n_min_timespan = retarget_timespan / 8;
            n_max_timespan = retarget_timespan * 4;
        } else {
            n_min_timespan = retarget_timespan / 16;
            n_max_timespan = retarget_timespan * 4;
        }

        // Limit adjustment step
        if n_modulated_timespan < n_min_timespan {
            n_modulated_timespan = n_min_timespan;
        } else if n_modulated_timespan > n_max_timespan {
            n_modulated_timespan = n_max_timespan;
        }

        // Retarget
        let bn_pow_limit = self.params.pow_limit;
        let mut bn_new = BlockHeader::u256_from_compact_target(pindex_last.bits);
        bn_new = bn_new.mul_u32(n_modulated_timespan.try_into().unwrap());
        bn_new = bn_new / Target::from_u64(retarget_timespan as u64).unwrap();

        if bn_new > bn_pow_limit {
            bn_new = bn_pow_limit;
        }

        BlockHeader::compact_target_from_u256(&bn_new)
    }

    /// Validate a block header as a potential new tip. This performs full header validation.
    fn validate(
        &self,
        tip: &CachedBlock,
        header: &BlockHeader,
        clock: &impl Clock,
    ) -> Result<(), Error> {
        assert_eq!(tip.hash(), header.prev_blockhash);

        let compact_target = match self.params.network {
            Network::DOGECOINMAINNET | Network::DOGECOINREGTEST | Network::DOGECOINTESTNET => {
                self.calculate_doge_compact_target(tip, header)
            }
            _ => {
                if self.params.allow_min_difficulty_blocks
                    && (tip.height + 1) % self.params.difficulty_adjustment_interval() != 0
                {
                    if header.time > tip.time + self.params.pow_target_spacing as BlockTime * 2 {
                        block::pow_limit_bits(&self.params.network)
                    } else {
                        self.next_min_difficulty_target(&self.params)
                    }
                } else {
                    self.next_difficulty_target(tip.height, tip.time, tip.target(), &self.params)
                }
            }
        };

        #[cfg(feature = "test")]
            let target = BlockHeader::u256_from_compact_target(header.bits);
        #[cfg(not(feature = "test"))]
            let target = BlockHeader::u256_from_compact_target(compact_target);

        match self.params.network {
            Network::Mainnet | Network::Testnet | Network::Regtest | Network::Signet => {
                match header.validate_pow(&target) {
                    Err(BlockBadProofOfWork) => {
                        return Err(Error::InvalidBlockPoW);
                    }
                    Err(BlockBadTarget) => {
                        return Err(Error::InvalidBlockTarget(header.target(), target));
                    }
                    Err(_) => unreachable!(),
                    Ok(_) => {}
                }
            }
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET | Network::DOGECOINREGTEST => {
                // we have checked the pow when decoding
                // todo fix the testnet target checking
                if self.params.network.ne(&Network::DOGECOINTESTNET) {
                    if header.target() != target {
                        error!("target check failed: compact_target {:?}, header.bits {}, block: {}", compact_target.to_hex(), header.bits.to_hex(), header.block_hash());
                        return Err(Error::InvalidBlockTarget(header.target(), target));
                    }
                }
            }
        }

        // Validate against block checkpoints.
        let height = tip.height + 1;

        if let Some(checkpoint) = self.checkpoints.get(&height) {
            let hash = header.block_hash();

            if &hash != checkpoint {
                return Err(Error::InvalidBlockHash(hash, height));
            }
        }

        // A timestamp is accepted as valid if it is greater than the median timestamp of
        // the previous MEDIAN_TIME_SPAN blocks, and less than the network-adjusted
        // time + MAX_FUTURE_BLOCK_TIME.
        #[cfg(not(feature = "test"))]
        if header.time <= self.median_time_past(height) {
            return Err(Error::InvalidBlockTime(header.time, Ordering::Less));
        }
        #[cfg(not(feature = "test"))]
        if header.time > clock.block_time() + time::MAX_FUTURE_BLOCK_TIME {
            return Err(Error::InvalidBlockTime(header.time, Ordering::Greater));
        }

        Ok(())
    }

    /// Get the next minimum-difficulty target. Only valid in testnet and regtest networks.
    fn next_min_difficulty_target(&self, params: &Params) -> Bits {
        assert!(params.allow_min_difficulty_blocks);

        let pow_limit_bits = block::pow_limit_bits(&params.network);

        for (height, header) in self.iter().rev() {
            if header.bits != pow_limit_bits
                || height % self.params.difficulty_adjustment_interval() == 0
            {
                return header.bits;
            }
        }
        pow_limit_bits
    }

    /// Get the next doge minimum-difficulty target. Only valid in testnet and regtest networks.
    fn doge_next_min_difficulty_target(&self, params: &Params, height: Height, difficulty_adjustment_interval: u64) -> Bits {
        assert!(params.doge_allow_min_difficulty_blocks(height));

        let pow_limit_bits = block::pow_limit_bits(&params.network);

        for (height, header) in self.iter().rev() {
            if header.bits != pow_limit_bits
                || height % difficulty_adjustment_interval == 0
            {
                return header.bits;
            }
        }
        pow_limit_bits
    }

    /// Rollback active chain to the given height. Returns the list of rolled-back headers.
    fn rollback(&mut self, height: Height) -> Result<Vec<(Height, BlockHeader)>, Error> {
        let mut stale = Vec::new();

        for (block, height) in self.chain.tail.drain(height as usize..).zip(height + 1..) {
            stale.push((height, block.header));

            self.chainwork = self.chainwork - block.work();
            self.headers.remove(&block.hash());
            self.orphans.insert(block.hash(), block.header);
        }
        self.store.rollback(height)?;

        Ok(stale)
    }

    /// Activate a fork candidate. Returns the list of rolled-back (stale) headers.
    fn switch_to_fork(&mut self, branch: &Candidate) -> Result<Vec<(Height, BlockHeader)>, Error> {
        let stale = self.rollback(branch.fork_height)?;

        for (i, header) in branch.headers.iter().enumerate() {
            self.extend_chain(
                branch.fork_height + i as Height + 1,
                header.block_hash(),
                *header,
            );
        }
        self.store.put(branch.headers.iter().cloned())?;

        Ok(stale)
    }

    /// Extend the active chain with a block.
    fn extend_chain(&mut self, height: Height, hash: BlockHash, header: BlockHeader) {
        assert_eq!(header.prev_blockhash, self.chain.last().hash());

        self.headers.insert(hash, height);
        self.orphans.remove(&hash);
        self.chain.push(CachedBlock { height, header });
        self.chainwork = self.chainwork + header.work();
    }

    /// Get the blocks starting from the given height.
    fn chain_suffix(&self, height: Height) -> &[CachedBlock] {
        &self.chain.tail[height as usize..]
    }
}

impl<S: Store<Header=BlockHeader>> BlockTree for BlockCache<S> {
    /// Import blocks into the block tree. Blocks imported this way don't have to form a chain.
    fn import_blocks<I: Iterator<Item=BlockHeader>, C: Clock>(
        &mut self,
        chain: I,
        context: &C,
    ) -> Result<ImportResult, Error> {
        let mut seen = BTreeSet::new();
        let mut reverted = BTreeMap::new();
        let mut connected = BTreeMap::new();
        let mut best_height = self.height();
        let mut best_hash = self.chain.last().hash();
        let mut best_header = self.chain.last().header;

        for (i, header) in chain.enumerate() {
            match self.import_block(header, context) {
                Ok(ImportResult::TipChanged {
                       header,
                       hash,
                       height,
                       reverted: r,
                       connected: c,
                   }) => {
                    seen.extend(c.iter().map(|(_, h)| h.block_hash()));
                    reverted.extend(r.into_iter().map(|(i, h)| ((i, h.block_hash()), h)));
                    connected.extend(c);

                    best_hash = hash;
                    best_height = height;
                    best_header = header;
                }
                Ok(ImportResult::TipUnchanged) => {}
                Err(Error::DuplicateBlock(hash)) => log::trace!("Duplicate block {}", hash),
                Err(Error::BlockMissing(hash)) => log::trace!("Missing block {}", hash),
                Err(err) => return Err(Error::BlockImportAborted(err.into(), i, self.height())),
            }
        }

        if !connected.is_empty() {
            // Don't return reverted blocks if they were seen as connected at some point, since
            // we only want to include blocks reverted from the main chain.
            reverted.retain(|(_, h), _| !seen.contains(h) && !self.contains(h));
            // Don't return connected blocks if they are not in the main chain.
            connected.retain(|_, h| self.contains(&h.block_hash()));

            Ok(ImportResult::TipChanged {
                header: best_header,
                hash: best_hash,
                height: best_height,
                reverted: reverted
                    .into_iter()
                    .rev()
                    .map(|((i, _), h)| (i, h))
                    .collect(),
                connected: NonEmpty::from_vec(connected.into_iter().collect()).expect(
                    "BlockCache::import_blocks: there is always at least one connected block",
                ),
            })
        } else {
            Ok(ImportResult::TipUnchanged)
        }
    }

    /// Extend the active chain.
    fn extend_tip<C: Clock>(
        &mut self,
        header: BlockHeader,
        clock: &C,
    ) -> Result<ImportResult, Error> {
        let tip = self.chain.last();
        let hash = header.block_hash();

        if header.prev_blockhash == tip.hash() {
            let height = tip.height + 1;

            self.validate(tip, &header, clock)?;
            self.extend_chain(height, hash, header);
            self.store.put(std::iter::once(header))?;

            Ok(ImportResult::TipChanged {
                header,
                hash,
                height,
                reverted: vec![],
                connected: NonEmpty::new((height, header)),
            })
        } else {
            Ok(ImportResult::TipUnchanged)
        }
    }
}

impl<S: Store<Header=BlockHeader>> BlockReader for BlockCache<S> {
    /// Get a block by hash. Only searches the active chain.
    fn get_block(&self, hash: &BlockHash) -> Option<(Height, &BlockHeader)> {
        self.headers
            .get(hash)
            .and_then(|height| self.chain.get(*height as usize))
            .map(|blk| (blk.height, &blk.header))
    }

    /// Get a block by height.
    fn get_block_by_height(&self, height: Height) -> Option<&BlockHeader> {
        self.chain.get(height as usize).map(|b| &b.header)
    }

    /// Find a branch.
    fn find_branch(&self, to: &BlockHash) -> Option<(Height, NonEmpty<BlockHeader>)> {
        // Check active chain first. If there's a match, the path to return is just the block
        // itself.
        if let Some((height, header)) = self.get_block(to) {
            return Some((height, NonEmpty::new(*header)));
        }

        // Since it's not in the active chain, check stale blocks.
        if let Some(Candidate {
                        fork_height,
                        fork_header,
                        headers,
                        ..
                    }) = self.fork(to)
        {
            Some((fork_height, NonEmpty::from((fork_header, headers))))
        } else {
            None
        }
    }

    /// Get the best block hash and header.
    fn tip(&self) -> (BlockHash, BlockHeader) {
        (self.chain.last().hash(), self.chain.last().header)
    }

    /// Get the "chainwork", ie. the total accumulated proof-of-work of the active chain.
    fn chain_work(&self) -> Uint256 {
        self.chainwork
    }

    /// Get the genesis block header.
    fn genesis(&self) -> &BlockHeader {
        &self.chain.first().header
    }

    /// Iterate over the longest chain, starting from genesis.
    fn iter<'a>(&'a self) -> Box<dyn DoubleEndedIterator<Item=(Height, BlockHeader)> + 'a> {
        Box::new(Iter::new(&self.chain).map(|(i, h)| (i, h.header)))
    }

    /// Iterate over a range of blocks.
    fn range<'a>(
        &'a self,
        range: std::ops::Range<Height>,
    ) -> Box<dyn Iterator<Item=(Height, BlockHash)> + 'a> {
        Box::new(
            self.chain
                .iter()
                .map(|block| (block.height, block.hash()))
                .skip(range.start as usize)
                .take((range.end - range.start) as usize),
        )
    }

    /// Return the height of the longest chain.
    fn height(&self) -> Height {
        self.chain.last().height
    }

    /// Get the height of the last checkpoint block.
    fn last_checkpoint(&self) -> Height {
        let height = self.height();

        self.checkpoints
            .iter()
            .rev()
            .map(|(h, _)| *h)
            .find(|h| *h <= height)
            .unwrap_or(0)
    }

    /// Known block checkpoints.
    fn checkpoints(&self) -> BTreeMap<Height, BlockHash> {
        self.checkpoints.clone()
    }

    /// Check whether this block hash is known.
    fn is_known(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash) || self.orphans.contains_key(hash)
    }

    /// Check whether this block hash is part of the active chain.
    fn contains(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash)
    }

    /// Return headers after the first known hash in the locators list, and until the stop hash
    /// is reached.
    ///
    /// This function will never return more than `max_headers`.
    ///
    /// * When no locators are provided, the stop hash is treated as a request for that header
    ///   alone.
    /// * When locators *are* provided, but none of them are known, it is equivalent to having
    ///   the genesis hash as locator.
    ///
    fn locate_headers(
        &self,
        locators: &[BlockHash],
        stop_hash: BlockHash,
        max_headers: usize,
    ) -> Vec<BlockHeader> {
        if locators.is_empty() {
            if let Some((_, header)) = self.get_block(&stop_hash) {
                return vec![*header];
            }
            return vec![];
        }

        // Start from the highest locator hash that is on our active chain.
        // We don't respond with anything if none of the locators were found.
        let start = if let Some(hash) = locators.iter().find(|h| self.contains(h)) {
            let (height, _) = self.get_block(hash).unwrap();
            height
        } else {
            0
        };

        let start = start + 1;
        let stop = self
            .get_block(&stop_hash)
            .map(|(h, _)| h)
            .unwrap_or_else(|| self.height());
        let stop = Height::min(start + max_headers as Height, stop + 1);

        if start > stop {
            return vec![];
        }

        self.range(start..stop).map(|h| h.header).collect()
    }

    /// Get the locator hashes for the active chain, starting at the given height.
    ///
    /// *Panics* if the given starting height is out of bounds.
    ///
    fn locator_hashes(&self, from: Height) -> Vec<BlockHash> {
        let mut hashes = Vec::new();

        assert!(from <= self.height());

        let last_checkpoint = self.last_checkpoint();

        for height in block::locators_indexes(from).into_iter() {
            if height < last_checkpoint {
                // Don't go past the latest checkpoint. We never want to accept a fork
                // older than our last checkpoint.
                break;
            }
            if let Some(blk) = self.chain.get(height as usize) {
                hashes.push(blk.hash());
            }
        }
        hashes
    }
}

#[cfg(test)]
mod test_doge {
    use nakamoto_common::bitcoin::BlockHeader;
    use nakamoto_common::network::Network;
    use nakamoto_common::params::Params;
    use crate::cache::{BlockCache, CachedBlock};
    use nakamoto_common::bitcoin::consensus::deserialize;
    use nakamoto_common::bitcoin_hashes::hex::ToHex;
    use nakamoto_common::block::{Bits, BlockTime, Height};
    use nakamoto_common::nonempty::NonEmpty;
    use crate::store;

    fn test_calculate_dogecoin_next_work_required(
        network: Network,
        pindex_last_header: CachedBlock,
        n_first_block_time: BlockTime,
        expected_bit: &str,
    ) {
        let genesis = network.genesis();
        let params = Params::new(network);
        let store = store::Memory::new(NonEmpty::new(genesis));
        let cache = BlockCache::from(store, params, &[]).unwrap();

        let new_bits = cache.calculate_dogecoin_next_work_required(&pindex_last_header, n_first_block_time);
        println!("new_bits {}", new_bits);
        println!("new_bits {}", new_bits.to_hex());
        let result = hex::decode(expected_bit).unwrap();
        let mut buf = [0; 4];
        buf.copy_from_slice(&result);
        let expected = u32::from_be_bytes(buf);
        println!("expected {expected}");
        assert_eq!(new_bits, expected)
    }

    #[test]
    fn test_cal_doge_target() {
        //get_next_work_difficulty_limit
        println!("get_next_work_difficulty_limit");
        let header_bytes = hex::decode("010000006c1d7587f53e1a90a2e05a7c7757e75a4d0ec971f6c885f5f780b546500cf4048f5d12df35bbf5906a36f9169f49e5907d747a049f01b944c478243702d3e17c76f0a352f0ff0f1e000244ec").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 239,
                header: pindex_last_header,
            },
            1386474927,
            "1e00ffff",
        );

        // test_get_next_work_pre_digishield
        println!();
        println!();
        println!("test_get_next_work_pre_digishield");
        let header_bytes = hex::decode("0100000011eb3fb946eaa19c8a321ebe21afb59f3fb052e9a56df68f4dad837ce05780da0735480f6ec6b3582d42cd081bcaf5d9b3fc764e7a9343c10de515307ae90fdc813dab5206121a1c00f95ce3").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 9599,
                header: pindex_last_header,
            },
            1386942008,
            "1c15ea59",
        );

        // get_next_work_digishield
        println!();
        println!();
        println!("get_next_work_digishield");
        let header_bytes = hex::decode("0200000058054081d6f4a30d6976ac03be7e3890f67fd8331613bb7ab95eb4b40d389a91339c41b140270652190c0ae3c31f8dbd400719b2ebe1cf8858a75ad6dc14663197742753fd9d491b00299347").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 145000,
                header: pindex_last_header,
            },
            1395094427,
            "1b671062",
        );

        // get_next_work_digishield_modulated_upper
        println!();
        println!();
        println!("get_next_work_digishield_modulated_upper");
        let header_bytes = hex::decode("020000007d373ddbd6ae5eafec37346a1b2253d9e04e02e36aa5567bf7985aac929b610612c8bec8263ef9f06b50ece2fc3747892526369fdf45cf76d7b92e735221477db08e2753cd39341b00250bce").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 145107,
                header: pindex_last_header,
            },
            1395100835,
            "1b4e56b3",
        );

        // get_next_work_digishield_modulated_lower
        println!();
        println!();
        println!("get_next_work_digishield_modulated_lower");
        let header_bytes = hex::decode("02000000335fb627c94002c46c8b9ca16b6835c1343c465390ddd87dbf25c134e8a662a27c597ea423e807c40ab788c294a75ef6bb515dd369f86fa3e8786cf7e16abeb2dfd02b53216f441b002fa9b9").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 149423,
                header: pindex_last_header,
            },
            1395380517,
            "1b335358",
        );

        // get_next_work_digishield_rounding
        println!();
        println!();
        println!("get_next_work_digishield_rounding");
        let header_bytes = hex::decode("0200000072de7b9bffdf6da71f07394a7d0859de1d3366a214328d82925c7c0de7ca47ccc423aa06735181ced11e841d8cd0fb55abe09948625db95698f54e3ec78d73b3c77427536210671b00cafd9b").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINMAINNET,
            CachedBlock {
                height: 145001,
                header: pindex_last_header,
            },
            1395094679,
            "1b6558a4",
        );
    }

    #[test]
    fn test_doge_testnet() {
        let header_bytes = hex::decode("02000000174ec3144dc795d1ff13712e5d829bbd06d504c1a26574190a9da0815e50cd8c517778747da783ab4dd37cb5febcd4cf850d5db67d3c3289bea0af6a8f271c4e4609fe52ffff0f1e3b770400").unwrap();
        let pindex_last_header: BlockHeader = deserialize(&header_bytes).unwrap();
        test_calculate_dogecoin_next_work_required(
            Network::DOGECOINTESTNET,
            CachedBlock {
                height: 239,
                header: pindex_last_header,
            },
            1392181003,
            "1e00ffff",
        );
    }
}