//! Compact Block Filter Manager.
//!
//! Manages BIP 157/8 compact block filter sync.
//!
mod rescan;

use std::collections::BTreeSet;
use std::ops::{Bound, RangeInclusive};

use thiserror::Error;

use nakamoto_common::bitcoin::network::constants::ServiceFlags;
use nakamoto_common::bitcoin::network::message::NetworkMessage;
use nakamoto_common::bitcoin::network::message_filter::{CFHeaders, CFilter, GetCFHeaders};
use nakamoto_common::bitcoin::{Script, Transaction, Txid};
use nakamoto_common::block::filter::{self, BlockFilter, Filters};
use nakamoto_common::block::time::{Clock, LocalDuration, LocalTime};
use nakamoto_common::block::tree::BlockReader;
use nakamoto_common::block::{BlockHash, Height};
use nakamoto_common::collections::{AddressBook, HashMap};
use nakamoto_common::network::Network;
use nakamoto_common::source;

use super::event::TxStatus;
use super::filter_cache::FilterCache;
use super::output::{Io, Outbox};
use super::{BlockSource, DisconnectReason, Event, Link, PeerId};

use rescan::Rescan;
use crate::fsm::{DOGECOIN_PROTOCOL_VERSION, PROTOCOL_VERSION};

/// Idle timeout.
pub const IDLE_TIMEOUT: LocalDuration = LocalDuration::from_secs(60);

/// Services required from peers for BIP 158 functionality.
pub const REQUIRED_SERVICES: ServiceFlags = ServiceFlags::COMPACT_FILTERS;

/// Maximum filter headers to be expected in a message.
pub const MAX_MESSAGE_CFHEADERS: usize = 2000;

/// Maximum filters to be expected in a message.
pub const MAX_MESSAGE_CFILTERS: usize = 1000;

/// Filter cache capacity in bytes.
pub const DEFAULT_FILTER_CACHE_SIZE: usize = 1024 * 1024; // 1 MB.

/// How long to wait to receive a reply from a peer.
pub const DEFAULT_REQUEST_TIMEOUT: LocalDuration = LocalDuration::from_secs(6);

/// An error originating in the CBF manager.
#[derive(Error, Debug)]
pub enum Error {
    /// The request was ignored. This happens if we're not able to fulfill the request.
    #[error("ignoring message from {from}: {reason}")]
    Ignored {
        /// Reason.
        reason: &'static str,
        /// Message sender.
        from: PeerId,
    },
    /// Error due to an invalid peer message.
    #[error("invalid message received from {from}: {reason}")]
    InvalidMessage {
        /// Message sender.
        from: PeerId,
        /// Reason why the message is invalid.
        reason: &'static str,
    },
    /// Error with the underlying filters datastore.
    #[error("{message}: {error}")]
    Filters {
        message: &'static str,
        error: filter::Error,
    },
}

/// An error from attempting to get compact filters.
#[derive(Error, Debug)]
pub enum GetFiltersError {
    /// The specified range is invalid, eg. it is out of bounds.
    #[error("the specified range is invalid")]
    InvalidRange,
    /// Not connected to any compact filter peer.
    #[error("not connected to any peer with compact filters support")]
    NotConnected,
}

/// CBF manager configuration.
#[derive(Debug)]
pub struct Config {
    /// How long to wait for a response from a peer.
    pub request_timeout: LocalDuration,
    /// Filter cache size, in bytes.
    pub filter_cache_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            filter_cache_size: DEFAULT_FILTER_CACHE_SIZE,
        }
    }
}

/// A CBF peer.
#[derive(Debug)]
struct Peer {
    #[allow(dead_code)]
    height: Height,
    #[allow(dead_code)]
    last_active: LocalTime,
    persistent: bool,
}

/// A compact block filter manager.
#[derive(Debug)]
pub struct FilterManager<F, C> {
    /// Rescan state.
    pub rescan: Rescan,
    /// Filter header chain.
    pub filters: F,

    config: Config,
    peers: AddressBook<PeerId, Peer>,
    outbox: Outbox,
    clock: C,
    /// Last time we idled.
    last_idle: Option<LocalTime>,
    /// Last time a filter was processed.
    /// We use this to figure out when to re-issue filter requests.
    last_processed: Option<LocalTime>,
    /// Pending block requests.
    pending_blocks: BTreeSet<Height>,
    /// Inflight requests.
    inflight: HashMap<BlockHash, (Height, PeerId, LocalTime)>,
}

impl<F, C> Iterator for FilterManager<F, C> {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        self.outbox.next()
    }
}

impl<F: Filters, C: Clock> FilterManager<F, C> {
    /// Create a new filter manager.
    pub fn new(config: Config, rng: fastrand::Rng, filters: F, clock: C, network: Network) -> Self {
        let peers = AddressBook::new(rng.clone());
        let rescan = Rescan::new(config.filter_cache_size);

        let protocol_version = match network {
            Network::Mainnet | Network::Testnet | Network::Regtest | Network::Signet => PROTOCOL_VERSION,
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET | Network::DOGECOINREGTEST => DOGECOIN_PROTOCOL_VERSION
        };
        let outbox = Outbox::new(protocol_version);

        Self {
            config,
            peers,
            rescan,
            outbox,
            clock,
            filters,
            pending_blocks: BTreeSet::new(),
            inflight: HashMap::with_hasher(rng.into()),
            last_idle: None,
            last_processed: None,
        }
    }

    /// Initialize the manager. Should only be called once.
    pub fn initialize<T: BlockReader>(&mut self, tree: &T) {
        self.idle(tree);
    }

    /// Event received.
    pub fn received_event<T: BlockReader, B: BlockSource>(
        &mut self,
        event: Event,
        tree: &T,
        blocks: &mut B,
    ) {
        match event {
            Event::PeerNegotiated {
                addr,
                link,
                services,
                height,
                persistent,
                ..
            } => {
                self.peer_negotiated(addr, height, services, link, persistent, tree);
            }
            Event::PeerDisconnected { addr, .. } => {
                self.peers.remove(&addr);
            }
            Event::BlockProcessed { block, height, .. } => {
                if self.pending_blocks.remove(&height) {
                    self.outbox.event(Event::BlockMatched { block, height });

                    // Since blocks are processed and matched in-order, we know this is the latest
                    // block that has matched.
                    // If there are no pending blocks however, it means there are no other matches,
                    // therefore we can jump to the current rescan height.
                    let height = if self.pending_blocks.is_empty() {
                        self.rescan.current.max(height)
                    } else {
                        height
                    };
                    self.outbox.event(Event::Scanned { height });
                }
            }
            Event::BlockDisconnected { height, .. } => {
                // In case of a re-org, make sure we don't accept old blocks that were requested.
                self.pending_blocks.remove(&height);
            }
            Event::BlockHeadersImported { reverted, .. } => {
                // Nb. the reverted blocks are ordered from the tip down to
                // the oldest ancestor.
                if let Some((height, _)) = reverted.last() {
                    // The height we need to rollback to, ie. the tip of our new chain
                    // and the tallest block we are keeping.
                    let fork_height = height - 1;

                    if let Err(e) = self.rollback(fork_height) {
                        self.outbox.error(e);
                    }
                }
                // Trigger a filter sync, since we're going to have to catch up on the
                // new block header(s). This is not required, but reduces latency.
                //
                // In the case of a re-org, this will trigger a re-download of the
                // missing headers after the rollback.
                self.sync(tree);
            }
            Event::TxStatusChanged { txid, status } => match status {
                TxStatus::Confirmed { .. } => {
                    self.unwatch_transaction(&txid);
                }
                TxStatus::Reverted { transaction } => {
                    self.watch_transaction(&transaction);
                }
                _ => {}
            },
            Event::MessageReceived { from, message } => match message.as_ref() {
                NetworkMessage::CFHeaders(msg) => {
                    log::debug!(
                        target: "p2p",
                        "Received {} filter header(s) from {}",
                        msg.filter_hashes.len(),
                        from
                    );

                    match self.received_cfheaders(&from, msg.clone(), tree) {
                        Ok(_) => {}
                        Err(Error::InvalidMessage { from, .. }) => {
                            self.outbox.event(Event::PeerMisbehaved {
                                addr: from,
                                reason: "invalid `cfheaders` message",
                            });
                        }
                        Err(e @ Error::Filters { .. }) => {
                            self.outbox.error(e);
                        }
                        Err(e @ Error::Ignored { .. }) => {
                            log::warn!(target: "p2p", "Dropped `cfheaders` message: {e}");
                        }
                    }
                }
                NetworkMessage::GetCFHeaders(msg) => {
                    match self.received_getcfheaders(&from, msg.clone(), tree) {
                        Ok(_) => {}
                        Err(Error::InvalidMessage { from, .. }) => {
                            self.outbox.event(Event::PeerMisbehaved {
                                addr: from,
                                reason: "invalid `getcfheaders` message",
                            });
                        }
                        Err(e @ Error::Filters { .. }) => {
                            self.outbox.error(e);
                        }
                        Err(e @ Error::Ignored { .. }) => {
                            log::warn!(target: "p2p", "Dropped `getcfheaders` message: {e}");
                        }
                    }
                }
                NetworkMessage::CFilter(msg) => {
                    match self.received_cfilter(&from, msg.clone(), tree) {
                        Ok(matches) => {
                            for (height, hash) in matches {
                                if self.pending_blocks.insert(height) {
                                    blocks.get_block(hash);
                                }
                            }
                            // Filters being processed only updates our progress if there are no
                            // pending blocks. Otherwise we have to wait for the block to arrive.
                            if self.pending_blocks.is_empty() {
                                self.outbox.event(Event::Scanned {
                                    height: self.rescan.current,
                                });
                            }
                        }
                        Err(Error::InvalidMessage { from, .. }) => {
                            self.outbox.event(Event::PeerMisbehaved {
                                addr: from,
                                reason: "invalid `cfilter` message",
                            });
                        }
                        Err(e @ Error::Filters { .. }) => {
                            self.outbox.error(e);
                        }
                        Err(e @ Error::Ignored { .. }) => {
                            log::warn!(target: "p2p", "Dropped `cfilter` message: {e}");
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// A tick was received.
    pub fn timer_expired<T: BlockReader>(&mut self, tree: &T) {
        self.idle(tree);

        let timeout = self.config.request_timeout;
        let now = self.clock.local_time();

        // Check if any header request expired. If so, retry with a different peer and disconnect
        // the unresponsive peer.
        for (stop_hash, (start_height, addr, expiry)) in &mut self.inflight {
            if now >= *expiry {
                let (start_height, stop_hash) = (*start_height, *stop_hash);

                // Nb. Purposefully allow re-sampling the same peer, for cases where we are only
                // connected to one peer.
                if let Some((a, peer)) = self.peers.sample() {
                    let a = *a;
                    // Disconnect only if we found a different peer, and this isn't
                    // a persistent peer.
                    if a != *addr && !peer.persistent {
                        self.peers.remove(addr);
                        self.outbox
                            .disconnect(*addr, DisconnectReason::PeerTimeout("getcfheaders"));
                    }
                    self.outbox
                        .get_cfheaders(a, start_height, stop_hash, timeout);

                    *addr = a;
                    *expiry = now + timeout;
                }
            }
        }

        // If we've waited too long since the last processed filter, re-issue requests
        // for missing filters.
        if now - self.last_processed.unwrap_or_default() >= DEFAULT_REQUEST_TIMEOUT {
            if self.rescan.active {
                self.rescan.reset(); // Clear pending request queue.
                self.get_cfilters(self.rescan.current..=self.filters.height(), tree)
                    .ok();
            }
        }
    }

    /// Add scripts to the list of scripts to watch.
    pub fn watch(&mut self, scripts: Vec<Script>) {
        self.rescan.watch.extend(scripts);
    }

    /// Add transaction outputs to list of transactions to watch.
    pub fn watch_transaction(&mut self, tx: &Transaction) {
        self.rescan.transactions.insert(
            tx.txid(),
            tx.output.iter().map(|o| o.script_pubkey.clone()).collect(),
        );
    }

    /// Rescan compact block filters.
    pub fn rescan<T: BlockReader>(
        &mut self,
        start: Bound<Height>,
        end: Bound<Height>,
        watch: Vec<Script>,
        tree: &T,
    ) -> Vec<(Height, BlockHash)> {
        self.rescan.restart(
            match start {
                Bound::Unbounded => tree.height() + 1,
                Bound::Included(h) => h,
                Bound::Excluded(h) => h + 1,
            },
            match end {
                Bound::Unbounded => None,
                Bound::Included(h) => Some(h),
                Bound::Excluded(h) => Some(h - 1),
            },
            watch,
        );

        self.outbox.event(Event::FilterRescanStarted {
            start: self.rescan.start,
            stop: self.rescan.end,
        });

        if self.rescan.watch.is_empty() {
            return vec![];
        }

        let height = self.filters.height();
        let start = self.rescan.start;
        let stop = self
            .rescan
            .end
            // Don't request further than the filter chain height.
            .map(|h| Height::min(h, height))
            .unwrap_or(height);
        let range = start..=stop;

        if range.is_empty() {
            return vec![];
        }

        // Start fetching the filters we can.
        match self.get_cfilters(range, tree) {
            Ok(()) => {}
            Err(GetFiltersError::NotConnected) => {}
            Err(err) => panic!("{}: Error fetching filters: {}", source!(), err),
        }
        // When we reset the rescan range, there is the possibility of getting immediate cache
        // hits from `get_cfilters`. Hence, process the filter queue.
        let (matches, events, _) = self.rescan.process();
        for event in events {
            self.outbox.event(event);
        }
        matches
    }

    /// Send one or more `getcfilters` messages to random peers.
    ///
    /// If the range is greater than [`MAX_MESSAGE_CFILTERS`], request filters from multiple
    /// peers.
    pub fn get_cfilters<T: BlockReader>(
        &mut self,
        range: RangeInclusive<Height>,
        tree: &T,
    ) -> Result<(), GetFiltersError> {
        if self.peers.is_empty() {
            return Err(GetFiltersError::NotConnected);
        }
        if range.is_empty() {
            return Err(GetFiltersError::InvalidRange);
        }
        assert!(*range.end() <= self.filters.height());

        // TODO: Only ask peers synced to a certain height.
        // Choose a different peer for each requested range.
        for (range, peer) in self
            .rescan
            .requests(range, tree)
            .into_iter()
            .zip(self.peers.cycle())
        {
            let stop_hash = tree
                .get_block_by_height(*range.end())
                .ok_or(GetFiltersError::InvalidRange)?
                .block_hash();
            let timeout = self.config.request_timeout;

            log::debug!(
                target: "p2p",
                "Requested filter(s) in range {} to {} from {} (stop = {})",
                range.start(),
                range.end(),
                peer,
                stop_hash
            );

            self.outbox
                .get_cfilters(*peer, *range.start(), stop_hash, timeout);
        }

        Ok(())
    }

    // PRIVATE METHODS /////////////////////////////////////////////////////////

    /// Rollback filters to the given height.
    fn rollback(&mut self, height: Height) -> Result<(), filter::Error> {
        // It's possible that a rollback doesn't affect the filter chain, if the filter headers
        // haven't caught up to the block headers when the re-org happens.
        if height >= self.filters.height() {
            return Ok(());
        }

        // Purge stale block filters.
        self.rescan.rollback(height);
        // Rollback filter header chain.
        self.filters.rollback(height)?;

        // Nb. Inflight filter header requests for heights that were rolled back will be ignored
        // when received.
        //
        // TODO: Inflight filter requests need to be re-issued.

        if self.rescan.active {
            // Reset "current" scanning height.
            //
            // We start re-scanning from either the start, or the current height, whichever
            // is greater, while ensuring that we only reset backwards, ie. we never skip
            // heights.
            //
            // For example, given we are currently at 7, if we rolled back to height 4, and our
            // start is at 5, we restart from 5.
            //
            // If we rolled back to height 4 and our start is at 3, we restart at 4, because
            // we don't need to scan blocks before our start height.
            //
            // If we rolled back to height 9 from height 11, we wouldn't want to re-scan any
            // blocks, since we haven't yet gotten to that height.
            //
            let start = self.rescan.start;
            let current = self.rescan.current;

            if current > height + 1 {
                self.rescan.current = Height::max(height + 1, start);
            }

            log::debug!(
                target: "p2p",
                "Rollback from {} to {}, start = {}, height = {}",
                current,
                self.rescan.current,
                start,
                height
            );
        }

        Ok(())
    }

    /// Called when a new peer was negotiated.
    fn peer_negotiated<T: BlockReader>(
        &mut self,
        addr: PeerId,
        height: Height,
        services: ServiceFlags,
        link: Link,
        persistent: bool,
        tree: &T,
    ) {
        if !link.is_outbound() {
            return;
        }
        if !services.has(REQUIRED_SERVICES) {
            return;
        }
        let time = self.clock.local_time();

        self.peers.insert(
            addr,
            Peer {
                last_active: time,
                height,
                persistent,
            },
        );
        self.sync(tree);
    }

    /// Attempt to sync the filter header chain.
    fn sync<T: BlockReader>(&mut self, tree: &T) {
        let filter_height = self.filters.height();
        let block_height = tree.height();

        assert!(filter_height <= block_height);

        // Don't start syncing filter headers until block headers are synced passed the last
        // checkpoint. BIP 157 states that we should sync the full block header chain before
        // syncing any filter headers, but this seems impractical. We choose a middle-ground.
        if let Some(checkpoint) = tree.checkpoints().keys().next_back() {
            if &block_height < checkpoint {
                return;
            }
        }

        if filter_height < block_height {
            log::debug!(
                target: "p2p",
                "Filter header chain is behind block header chain by {} header(s)",
                block_height - filter_height
            );
            // We need to sync the filter header chain.
            let start_height = self.filters.height() + 1;
            let stop_height = tree.height();

            self.send_getcfheaders(start_height..=stop_height, tree);
        }

        if self.rescan.active {
            // TODO: Don't do this too often.
            self.get_cfilters(self.rescan.current..=self.filters.height(), tree)
                .ok();
        }
    }

    /// Remove transaction from list of transactions being watch.
    fn unwatch_transaction(&mut self, txid: &Txid) -> bool {
        self.rescan.transactions.remove(txid).is_some()
    }

    /// Handle a `cfheaders` message from a peer.
    ///
    /// Returns the new filter header height, or an error.
    fn received_cfheaders<T: BlockReader>(
        &mut self,
        from: &PeerId,
        msg: CFHeaders,
        tree: &T,
    ) -> Result<Height, Error> {
        let from = *from;
        let stop_hash = msg.stop_hash;

        if self.inflight.remove(&stop_hash).is_none() {
            return Err(Error::Ignored {
                from,
                reason: "unsolicited `cfheaders` message",
            });
        }

        if msg.filter_type != 0x0 {
            return Err(Error::InvalidMessage {
                from,
                reason: "invalid `cfheaders` filter type",
            });
        }

        let start_height = self.filters.height();
        let stop_height = if let Some((height, _)) = tree.get_block(&stop_hash) {
            height
        } else {
            return Err(Error::InvalidMessage {
                from,
                reason: "unknown `cfheaders` stop hash",
            });
        };

        // If we've already synced up to the stop hash, ignore.
        if stop_height <= self.filters.height() {
            return Ok(self.filters.height());
        }

        let (_, tip_header) = self.filters.tip();
        let prev_header = msg.previous_filter_header;

        // If the previous header of the message does not match our tip, it could be
        // that our tip was updated while the message was inflight.
        // Schedule a wake to make sure we sync the correct range this time around.
        if &prev_header != tip_header {
            self.schedule_wake();

            return Err(Error::Ignored {
                reason: "previous filter header does not match local tip",
                from,
            });
        }

        let hashes = msg.filter_hashes;
        let count = hashes.len();

        if start_height > stop_height {
            return Err(Error::InvalidMessage {
                from,
                reason: "`cfheaders` start height is greater than stop height",
            });
        }

        if count > MAX_MESSAGE_CFHEADERS {
            return Err(Error::InvalidMessage {
                from,
                reason: "`cfheaders` header count exceeds maximum",
            });
        }

        if count == 0 {
            return Err(Error::InvalidMessage {
                from,
                reason: "`cfheaders` has an empty header list",
            });
        }

        if (stop_height - start_height) as usize != count {
            return Err(Error::InvalidMessage {
                from,
                reason: "`cfheaders` header count does not match height range",
            });
        }

        // Ok, looks like everything's valid..

        let mut last_header = prev_header;
        let mut headers = Vec::with_capacity(count);

        // Create headers out of the hashes.
        for filter_hash in hashes {
            last_header = filter_hash.filter_header(&last_header);
            headers.push((filter_hash, last_header));
        }
        self.filters
            .import_headers(headers)
            .map(|height| {
                self.headers_imported(start_height, height, tree).unwrap(); // TODO

                assert!(height <= tree.height());

                if height == tree.height() {
                    self.outbox.event(Event::FilterHeadersSynced { height });
                } else {
                    self.sync(tree);
                }
                height
            })
            .map_err(|error| Error::Filters {
                message: "error importing filter headers",
                error,
            })
    }

    /// Handle a `getcfheaders` message from a peer.
    fn received_getcfheaders<T: BlockReader>(
        &mut self,
        from: &PeerId,
        msg: GetCFHeaders,
        tree: &T,
    ) -> Result<(), Error> {
        let from = *from;

        if msg.filter_type != 0x0 {
            return Err(Error::InvalidMessage {
                from,
                reason: "getcfheaders: invalid filter type",
            });
        }

        let start_height = msg.start_height as Height;
        let stop_height = if let Some((height, _)) = tree.get_block(&msg.stop_hash) {
            height
        } else {
            // Can't handle this message, we don't have the stop block.
            return Err(Error::Ignored {
                reason: "stop block missing",
                from,
            });
        };

        let headers = self.filters.get_headers(start_height..=stop_height);
        if !headers.is_empty() {
            let hashes = headers.iter().map(|(hash, _)| *hash);
            let prev_header = self.filters.get_prev_header(start_height).expect(
                "FilterManager::received_getcfheaders: all headers up to the tip must exist",
            );

            self.outbox.cfheaders(
                from,
                CFHeaders {
                    filter_type: msg.filter_type,
                    stop_hash: msg.stop_hash,
                    previous_filter_header: prev_header,
                    filter_hashes: hashes.collect(),
                },
            );
            return Ok(());
        }
        // We must be syncing, since we have the block headers requested but
        // not the associated filter headers. Simply ignore the request.
        Err(Error::Ignored {
            reason: "cfheaders not found",
            from,
        })
    }

    /// Handle a `cfilter` message.
    ///
    /// Returns a list of blocks that need to be fetched from the network.
    fn received_cfilter<T: BlockReader>(
        &mut self,
        from: &PeerId,
        msg: CFilter,
        tree: &T,
    ) -> Result<Vec<(Height, BlockHash)>, Error> {
        let from = *from;

        if msg.filter_type != 0x0 {
            return Err(Error::Ignored {
                reason: "wrong filter type",
                from,
            });
        }

        let height = if let Some((height, _)) = tree.get_block(&msg.block_hash) {
            height
        } else {
            // Can't handle this message, we don't have the block header.
            return Err(Error::Ignored {
                reason: "block header not found",
                from,
            });
        };

        // The expected hash for this block filter.
        let header = if let Some((_, header)) = self.filters.get_header(height) {
            header
        } else {
            // Can't handle this message, we don't have the header.
            return Err(Error::Ignored {
                reason: "filter header not found",
                from,
            });
        };

        // Note that in case this fails, we have a bug in our implementation, since filter
        // headers are supposed to be downloaded in-order.
        let prev_header = self
            .filters
            .get_prev_header(height)
            .expect("FilterManager::received_cfilter: all headers up to the tip must exist");
        let filter = BlockFilter::new(&msg.filter);
        let block_hash = msg.block_hash;

        if filter.filter_header(&prev_header) != header {
            return Err(Error::InvalidMessage {
                from,
                reason: "cfilter: filter hash doesn't match header",
            });
        }
        self.outbox.event(Event::FilterReceived {
            from,
            block: block_hash,
            height,
            filter: filter.clone(),
        });

        if self.rescan.received(height, filter, block_hash) {
            let (matches, events, processed) = self.rescan.process();
            for event in events {
                self.outbox.event(event);
            }
            // If we processed some filters, update the time to further delay requesting new
            // filters.
            if processed > 0 {
                self.last_processed = Some(self.clock.local_time());
            }
            return Ok(matches);
        } else {
            // Unsolicited filter.
        }
        Ok(Vec::default())
    }

    /// Called periodically. Triggers syncing if necessary.
    fn idle<T: BlockReader>(&mut self, tree: &T) {
        let now = self.clock.local_time();

        if now - self.last_idle.unwrap_or_default() >= IDLE_TIMEOUT {
            self.sync(tree);
            self.last_idle = Some(now);
            self.outbox.set_timer(IDLE_TIMEOUT);
        }
    }

    /// Send a `getcfheaders` message to a random peer.
    ///
    /// # Panics
    ///
    /// Panics if the range is not within the bounds of the active chain.
    ///
    fn send_getcfheaders<T: BlockReader>(
        &mut self,
        range: RangeInclusive<Height>,
        tree: &T,
    ) -> Option<(PeerId, Height, BlockHash)> {
        let (start, end) = (*range.start(), *range.end());

        debug_assert!(start <= end);
        debug_assert!(!range.is_empty());

        if range.is_empty() {
            return None;
        }
        // Cap requested header count.
        let count = usize::min(MAX_MESSAGE_CFHEADERS, (end - start + 1) as usize);
        let start_height = start;
        let stop_hash = {
            let stop_height = start + count as Height - 1;
            let stop_block = tree
                .get_block_by_height(stop_height)
                .unwrap_or_else(|| panic!("{}: Stop height is out of bounds", source!()));

            stop_block.block_hash()
        };

        self.get_cfheaders(start_height, stop_hash)
    }

    /// Lower level function that takes a start height and stop hash.
    fn get_cfheaders(
        &mut self,
        start_height: Height,
        stop_hash: BlockHash,
    ) -> Option<(PeerId, Height, BlockHash)> {
        if self.inflight.contains_key(&stop_hash) {
            // Don't request the same thing twice.
            return None;
        }
        // TODO: We should select peers that are caught up to the requested height.
        if let Some((peer, _)) = self.peers.sample() {
            let time = self.clock.local_time();
            let timeout = self.config.request_timeout;

            self.outbox
                .get_cfheaders(*peer, start_height, stop_hash, timeout);
            self.inflight
                .insert(stop_hash, (start_height, *peer, time + timeout));

            return Some((*peer, start_height, stop_hash));
        } else {
            // TODO: Emit 'NotConnected' event, and make sure we retry later, or when a
            // peer connects.
        }
        None
    }

    /// Called when filter headers were successfully imported.
    ///
    /// The height is the new filter header chain height, and the hash is the
    /// hash of the block corresponding to the last filter header.
    ///
    /// When new headers are imported, we want to download the corresponding compact filters
    /// to check them for matches.
    fn headers_imported<T: BlockReader>(
        &mut self,
        start: Height,
        stop: Height,
        tree: &T,
    ) -> Result<(), GetFiltersError> {
        if !self.rescan.active {
            return Ok(());
        }

        let start = Height::max(start, self.rescan.current);
        let stop = Height::min(stop, self.rescan.end.unwrap_or(stop));
        let range = start..=stop; // If the range is empty, it means we are not caught up yet.

        if !range.is_empty() {
            self.get_cfilters(range, tree)?;
        }
        Ok(())
    }

    fn schedule_wake(&mut self) {
        self.last_idle = None; // Disable rate-limiting for the next tick.
        self.outbox.set_timer(LocalDuration::from_secs(1));
    }
}

/// Iterator over height ranges.
struct HeightIterator {
    start: Height,
    stop: Height,
    step: Height,
}

impl Iterator for HeightIterator {
    type Item = RangeInclusive<Height>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.stop {
            let start = self.start;
            let stop = self.stop.min(start + self.step - 1);

            self.start = stop + 1;

            Some(start..=stop)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::ops::RangeBounds;

    use nakamoto_common::bitcoin;
    use nakamoto_common::bitcoin_hashes;

    use bitcoin::network::message::NetworkMessage;
    use bitcoin::network::message_filter::GetCFilters;
    use bitcoin::BlockHeader;
    use bitcoin_hashes::hex::FromHex;

    use nakamoto_chain::store::Genesis;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use nakamoto_chain::block::{cache::BlockCache, store};
    use nakamoto_chain::filter::cache::{FilterCache, StoredHeader};
    use nakamoto_common::block::filter::{FilterHash, FilterHeader};
    use nakamoto_common::block::time::RefClock;
    use nakamoto_common::block::tree::BlockReader as _;
    use nakamoto_common::block::tree::BlockTree;
    use nakamoto_common::block::tree::ImportResult;
    use nakamoto_common::network::Network;
    use nakamoto_common::nonempty::NonEmpty;
    use nakamoto_test::assert_matches;
    use nakamoto_test::block::gen;
    use nakamoto_test::BITCOIN_HEADERS;

    use crate::fsm::output;

    use super::*;

    mod util {
        use nakamoto_common::params::Params;
        use super::*;

        pub fn setup<C: Clock>(
            network: Network,
            height: Height,
            filter_cache_size: usize,
            clock: C,
        ) -> (
            FilterManager<FilterCache<store::Memory<StoredHeader>>, C>,
            BlockCache<store::Memory<BlockHeader>>,
            NonEmpty<bitcoin::Block>,
        ) {
            let mut rng = fastrand::Rng::new();
            let genesis = network.genesis_block();
            let chain = gen::blockchain(genesis, height, &mut rng);
            let tree = {
                let headers = NonEmpty::from_vec(chain.iter().map(|b| b.header).collect()).unwrap();
                let store = store::Memory::new(headers);
                let params = Params::new(network.into());

                BlockCache::from(store, params, &[]).unwrap()
            };
            let cfheaders =
                gen::cfheaders_from_blocks(FilterHeader::genesis(network), chain.tail.iter());

            let mut cache = FilterCache::load(store::memory::Memory::genesis(network)).unwrap();
            cache.import_headers(cfheaders).unwrap();
            cache.verify(network).unwrap();

            let config = Config {
                filter_cache_size,
                ..Config::default()
            };

            (FilterManager::new(config, rng, cache, clock, network), tree, chain)
        }

        pub fn cfilters<'a>(
            blocks: impl IntoIterator<Item = &'a bitcoin::Block> + 'a,
        ) -> impl Iterator<Item = CFilter> + 'a {
            blocks.into_iter().map(move |block| {
                let block_hash = block.block_hash();
                let filter = gen::cfilter(block);

                CFilter {
                    filter_type: 0x0,
                    block_hash,
                    filter: filter.content,
                }
            })
        }

        pub fn cfheaders(
            previous_filter_header: FilterHeader,
            blocks: &[bitcoin::Block],
        ) -> CFHeaders {
            let tip = blocks.last().unwrap().block_hash();
            let filter_hashes = gen::cfheaders_from_blocks(previous_filter_header, blocks.iter())
                .into_iter()
                .map(|(h, _)| h)
                .collect::<Vec<_>>();

            CFHeaders {
                filter_type: 0x0,
                stop_hash: tip,
                previous_filter_header,
                filter_hashes,
            }
        }

        pub fn extend<T, C>(
            tree: &mut T,
            n: usize,
            time: &C,
            rng: &mut fastrand::Rng,
        ) -> (Vec<bitcoin::Block>, BlockHash)
        where
            T: BlockTree,
            C: Clock,
        {
            let (_, tip) = tree.tip();
            let suffix = gen::fork(&tip, n, rng);
            let result = tree
                .import_blocks(suffix.iter().map(|b| b.header), time)
                .unwrap();

            if let ImportResult::TipChanged { hash, .. } = result {
                (suffix, hash)
            } else {
                panic!("unexpected import result: {:?}", result)
            }
        }

        #[allow(dead_code)]
        pub fn is_sorted<T>(data: &[T]) -> bool
        where
            T: Ord,
        {
            data.windows(2).all(|w| w[0] <= w[1])
        }
    }

    const FILTER_HASHES: [&str; 15] = [
        "9acd599f31639d36b8e531d12afb430bb17e7cdd6e73c993c343e417cda1f299",
        "0bfdf66fef865ea20f1a3c4d12a9570685aa89cdd8a950755ef7e870520533ad",
        "155215e98328f097cf085f721edff6f4e9e1072e14012052b86297aa21085dcb",
        "227a8f6d137745df7445afcc5b1484c5a70bd1edb2f2886943dcb396803d1d85",
        "fb86fad94ad95c042894083c7dce973406481b0fd674163fde5d4f52a7bc074d",
        "37a8db7d504b65c63f0d5559ab616e586257b3d0672d574e7fcc7018eb45aa35",
        "a1a81f3571c98b30ce69ddf2f9e6a014074d73327d0e0d6cdc4d493fe64e3f2a",
        "a16c3a9a9da80a10999f73e88fbf5cd63a0266115c5f1f683ee1f1c534ad232d",
        "f52a72367e64fffdbd5239c00f380db0ac77901a8a8faa9c642d592b87b4b7ca",
        "81c4c5606d54107bfb9dccbaf23b7a2459f8444816623ba23e3de91f16a525da",
        "1f64677b953cbc851277f95edb29065c7859cae744ef905b5950f8e79ed97c8a",
        "8cde7d77626801155a891eea0688d7eb5c37ca74d84493254ff4e4c2a886de4a",
        "3eb61e435e1ed1675b5c1fcc4a89b4dba3695a8b159aabe4c03833ecd7c41704",
        "802221cd81ad57748b713d8055b5fc6d5f7cef71b9d59d690857ef835704cab8",
        "503adfa2634006e453900717f070ffc11a639ee1a0416e4e137f396c7706e6b7",
    ];

    const FILTERS: [&[u8]; 11] = [
        &[1, 127, 168, 128],
        &[1, 140, 59, 16],
        &[1, 140, 120, 216],
        &[1, 19, 255, 16],
        &[1, 63, 182, 112],
        &[1, 56, 58, 48],
        &[1, 12, 113, 176],
        &[1, 147, 204, 216],
        &[1, 117, 5, 160],
        &[1, 141, 61, 184],
        &[1, 155, 155, 152],
    ];

    #[test]
    fn test_receive_filters() {
        let network = Network::Mainnet;
        let peer = &([0, 0, 0, 0], 0).into();
        let time = LocalTime::now();
        let clock = RefClock::from(time);
        let tree = {
            let genesis = network.genesis();
            let params = network.params();

            assert_eq!(genesis, BITCOIN_HEADERS.head);

            BlockCache::from(store::Memory::new(BITCOIN_HEADERS.clone()), params, &[]).unwrap()
        };
        let mut cbfmgr = {
            let rng = fastrand::Rng::new();
            let cache = FilterCache::load(store::memory::Memory::genesis(network)).unwrap();

            FilterManager::new(Config::default(), rng, cache, clock, network)
        };

        // Import the headers.
        {
            let msg = CFHeaders {
                filter_type: 0,
                stop_hash: BlockHash::from_hex(
                    "00000000b3322c8c3ef7d2cf6da009a776e6a99ee65ec5a32f3f345712238473",
                )
                .unwrap(),
                previous_filter_header: FilterHeader::from_hex(
                    "02c2392180d0ce2b5b6f8b08d39a11ffe831c673311a3ecf77b97fc3f0303c9f",
                )
                .unwrap(),
                filter_hashes: FILTER_HASHES
                    .iter()
                    .map(|h| FilterHash::from_hex(h).unwrap())
                    .collect(),
            };
            cbfmgr.inflight.insert(msg.stop_hash, (1, *peer, time));
            cbfmgr.received_cfheaders(peer, msg, &tree).unwrap();
        }

        assert_eq!(cbfmgr.filters.height(), 15);
        cbfmgr.filters.verify(network).unwrap();

        let cfilters = FILTERS
            .iter()
            .zip(BITCOIN_HEADERS.iter())
            .map(|(f, h)| CFilter {
                filter_type: 0x0,
                block_hash: h.block_hash(),
                filter: f.to_vec(),
            });

        // Now import the filters.
        for msg in cfilters {
            cbfmgr.received_cfilter(peer, msg, &tree).unwrap();
        }
    }

    #[test]
    fn test_height_iterator() {
        let mut it = super::HeightIterator {
            start: 3,
            stop: 19,
            step: 5,
        };
        assert_eq!(it.next(), Some(3..=7));
        assert_eq!(it.next(), Some(8..=12));
        assert_eq!(it.next(), Some(13..=17));
        assert_eq!(it.next(), Some(18..=19));
        assert_eq!(it.next(), None);
    }

    /// Test that we can start a rescan without any peers, and it'll pick up when peers connect.
    #[test]
    fn test_not_connected() {
        let best = 144;
        let mut rng = fastrand::Rng::new();
        let time = LocalTime::now();
        let network = Network::Regtest;
        let remote: PeerId = ([8, 8, 8, 8], 8333).into();
        let (mut cbfmgr, tree, _) = util::setup(network, best, 0, RefClock::from(time));

        // Start rescan with no peers.
        cbfmgr.rescan(
            Bound::Included(0),
            Bound::Unbounded,
            vec![gen::script(&mut rng)],
            &tree,
        );

        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );
        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| matches!(m, NetworkMessage::GetCFilters(_)))
            .unwrap();
    }

    /// Test that we don't make redundant `getcfilters` requests.
    #[test]
    #[ignore]
    fn test_redundant_requests() {
        todo!()
    }

    /// Test that we can specify a birth date in the future.
    #[test]
    #[ignore]
    fn test_rescan_future_birth() {
        todo!()
    }

    /// Test that an unbounded rescan will continuously ask for filters.
    #[test]
    #[ignore]
    fn test_rescan_unbouned() {
        todo!()
    }

    /// Test that a bounded rescan will eventually complete.
    #[test]
    #[ignore]
    fn test_rescan_completed() {
        todo!()
    }

    /// Test that rescanning triggers filter syncing immediately.
    #[test]
    fn test_rescan_getcfilters() {
        let birth = 11;
        let best = 42;
        let mut rng = fastrand::Rng::new();
        let time = LocalTime::now();
        let network = Network::Regtest;
        let (mut cbfmgr, tree, chain) = util::setup(network, best, 0, RefClock::from(time));
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let tip = tree.get_block_by_height(best).unwrap().block_hash();
        let filter_type = 0x0;
        let previous_filter_header = FilterHeader::genesis(network);
        let filter_hashes = gen::cfheaders_from_blocks(previous_filter_header, chain.iter())
            .into_iter()
            .skip(1) // Skip genesis
            .map(|(h, _)| h)
            .collect::<Vec<_>>();

        cbfmgr.filters.clear().unwrap();
        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );
        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| matches!(m, NetworkMessage::GetCFHeaders(_)))
            .unwrap();

        cbfmgr
            .received_cfheaders(
                &remote,
                CFHeaders {
                    filter_type,
                    stop_hash: tip,
                    previous_filter_header,
                    filter_hashes,
                },
                &tree,
            )
            .unwrap();

        // Start rescan.
        cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Unbounded,
            vec![gen::script(&mut rng)],
            &tree,
        );

        let expected = GetCFilters {
            filter_type,
            start_height: birth as u32,
            stop_hash: tip,
        };
        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| matches!(m, NetworkMessage::GetCFilters(msg) if msg == &expected))
            .expect("Rescanning should trigger filters to be fetched");
    }

    /// Test that `getcfilters` request is retried.
    #[test]
    fn test_rescan_getcfilters_retry() {
        let birth = 11;
        let best = 42;
        let mut rng = fastrand::Rng::new();
        let time = LocalTime::now();
        let network = Network::Regtest;
        let filter_type = 0x0;
        let (mut cbfmgr, tree, chain) = util::setup(network, best, 0, RefClock::from(time));
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let previous_filter_header = FilterHeader::genesis(network);
        let cfheaders = util::cfheaders(previous_filter_header, &chain.tail);
        let cfilters = util::cfilters(chain.iter()).collect::<Vec<_>>();

        cbfmgr.filters.clear().unwrap();
        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );
        cbfmgr
            .received_cfheaders(&remote, cfheaders, &tree)
            .unwrap();
        assert_eq!(cbfmgr.filters.height(), best);

        // Start rescan.
        cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Unbounded,
            vec![gen::script(&mut rng)],
            &tree,
        );
        assert!(cbfmgr.last_processed.is_none());
        assert_eq!(cbfmgr.rescan.current, birth);

        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| matches!(m, NetworkMessage::GetCFilters(_)))
            .expect("`getcfilters` sent");

        // Receive a filter, but not one that we can process immediately.
        cbfmgr
            .received_cfilter(&remote, cfilters[birth as usize + 1].clone(), &tree)
            .unwrap();

        assert!(cbfmgr.last_processed.is_none());
        assert_eq!(cbfmgr.rescan.current, birth);

        // Receive a filter, that we can process immediately.
        cbfmgr
            .received_cfilter(&remote, cfilters[birth as usize].clone(), &tree)
            .unwrap();

        // We should be futher along now.
        let current = birth + 2;

        assert!(cbfmgr.last_processed.is_some());
        assert_eq!(cbfmgr.rescan.current, current);

        // We still have filters we are waiting for, but let's let some time pass.
        cbfmgr.clock.elapse(DEFAULT_REQUEST_TIMEOUT);
        cbfmgr.timer_expired(&tree);

        // We expect a new request to be sent from the new starting height.
        let (stop_hash, _) = tree.tip();
        let expected = GetCFilters {
            filter_type,
            start_height: current as u32,
            stop_hash,
        };
        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| matches!(m, NetworkMessage::GetCFilters(msg) if msg == &expected))
            .expect("`getcfilters` sent");

        cbfmgr
            .received_cfilter(&remote, cfilters[current as usize].clone(), &tree)
            .unwrap();
        assert_eq!(cbfmgr.rescan.current, current + 1);
    }

    /// Test that if we start with our cfheader chain behind our header
    /// chain, we immediately try to catch up.
    #[test]
    fn test_cfheaders_behind() {
        let cfheader_height = 10;
        let header_height = 15;

        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let mut rng = fastrand::Rng::with_seed(772092983);
        let time = LocalTime::now();

        let mut cbfmgr = {
            let cache = FilterCache::load(store::memory::Memory::genesis(network)).unwrap();
            let rng = fastrand::Rng::new();
            FilterManager::new(Config::default(), rng, cache, time, network)
        };

        let chain = gen::blockchain(network.genesis_block(), header_height, &mut rng);
        let cfheaders = gen::cfheaders_from_blocks(
            FilterHeader::genesis(network),
            chain.tail.iter().take(cfheader_height),
        );
        cbfmgr.filters.import_headers(cfheaders).unwrap();

        let tree = {
            let params = network.params();
            let headers = NonEmpty::from_vec(chain.iter().map(|b| b.header).collect()).unwrap();
            BlockCache::from(store::Memory::new(headers), params, &[]).unwrap()
        };
        cbfmgr.initialize(&tree);

        cbfmgr.peer_negotiated(
            remote,
            header_height,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );

        let tip = chain.last();
        let outputs = cbfmgr.outbox.drain().collect::<Vec<_>>();
        let mut msgs = output::test::messages_from(outputs.iter().cloned(), &remote);

        msgs.find(|m| {
            matches!(
                m,
                NetworkMessage::GetCFHeaders(
                    GetCFHeaders { start_height, stop_hash, .. }
                ) if (*start_height as usize) == (cfheader_height + 1) && stop_hash == &tip.block_hash()
            )
        }).unwrap();
    }

    #[test]
    fn test_partial_cache_hit_overlap_max() {
        // Head              8
        // Cache    5  6  7  8  *
        // Rescan   *  *  7  8  9
        // Request  *  *  *  *  9
        let cache_range = 5..=8;
        let rescan_range = 7..=9;
        let cache_hits = [7, 8];
        let expected_request = 9;

        nakamoto_test::logger::init(log::Level::Debug);

        let mut rng = fastrand::Rng::new();
        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let birth: u64 = *cache_range.start();
        let best: u64 = *cache_range.end();

        let time = LocalTime::now();
        let (mut cbfmgr, mut tree, chain) =
            util::setup(network, best, DEFAULT_FILTER_CACHE_SIZE, time);
        let (watch, _) = gen::watchlist(birth, chain.iter());

        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );

        // 1. Populate the cache from heights 5 to 8.
        cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Included(best),
            watch.clone(),
            &tree,
        );

        for msg in util::cfilters(chain.iter().take(best as usize + 1)) {
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }
        assert_eq!(cbfmgr.rescan.cache.start(), Some(birth));
        assert_eq!(cbfmgr.rescan.cache.end(), Some(best));

        // 2. Advance the block header chain to 9.
        let extent = rescan_range.end() - cache_range.end();
        let (suffix, tip) = util::extend(&mut tree, extent as usize, &time, &mut rng);
        assert_eq!(tree.height(), *rescan_range.end());

        // 3. Advance the filter header chain to 9.
        cbfmgr.sync(&tree);

        let (_, parent) = cbfmgr.filters.tip();
        let cfheaders = util::cfheaders(*parent, &suffix);

        cbfmgr
            .received_cfheaders(&remote, cfheaders, &tree)
            .unwrap();
        assert_eq!(cbfmgr.filters.height(), *rescan_range.end());

        // 4. Make sure there's nothing in the outbox.
        cbfmgr.outbox.drain().for_each(drop);

        // 5. Trigger a rescan for the new range 7 to 9
        let matched = cbfmgr.rescan(
            rescan_range.start_bound().cloned(),
            rescan_range.end_bound().cloned(),
            watch,
            &tree,
        );

        // 6. Expect that 7 and 8 are cache hits, and 9 is requested.
        assert_eq!(
            matched
                .iter()
                .map(|(height, _)| *height)
                .collect::<Vec<_>>(),
            cache_hits
        );
        // TODO: Test that there are no other requests.
        assert_matches!(
            output::test::messages_from(&mut cbfmgr.outbox, &remote).next().unwrap(),
            NetworkMessage::GetCFilters(GetCFilters {
                start_height,
                stop_hash,
                ..
            }) if start_height as Height == expected_request && stop_hash == tip,
            "expected {} and {}", expected_request, tip
        );
    }

    #[test]
    fn test_partial_cache_hit_overlap_min() {
        // Head              9
        // Cache    *  7  8  9
        // Rescan   6  7  8  *
        // Request  6  *  *  *
        let cache_range = 7..=9;
        let rescan_range = 6..=8;
        let expected_request: Height = 6;

        nakamoto_test::logger::init(log::Level::Debug);

        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let birth: u64 = *cache_range.start();
        let best: u64 = *cache_range.end();

        let time = LocalTime::now();
        let (mut cbfmgr, tree, chain) = util::setup(network, best, DEFAULT_FILTER_CACHE_SIZE, time);
        let (watch, _) = gen::watchlist(birth, chain.iter());

        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );

        // 1. Populate the cache from heights 7 to 9.
        cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Included(best),
            watch.clone(),
            &tree,
        );

        for msg in util::cfilters(chain.iter().take(best as usize + 1)) {
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }
        assert_eq!(cbfmgr.rescan.cache.start(), Some(birth));
        assert_eq!(cbfmgr.rescan.cache.end(), Some(best));

        let (tip, _) = tree.tip();

        // 4. Make sure there's nothing in the outbox.
        cbfmgr.outbox.drain().for_each(drop);

        // 5. Trigger a rescan for the new range 6 to 8.
        // Nothing should be matched yet, since we don't have filter #6.
        let matched = cbfmgr.rescan(
            rescan_range.start_bound().cloned(),
            rescan_range.end_bound().cloned(),
            watch,
            &tree,
        );
        assert_eq!(matched, vec![]);

        // 6. Expect that #6 is requested.
        let missing = &chain[expected_request as usize];

        assert_matches!(
            output::test::messages_from(&mut cbfmgr.outbox, &remote).next().unwrap(),
            NetworkMessage::GetCFilters(GetCFilters {
                start_height,
                stop_hash,
                ..
            }) if start_height as Height == expected_request && stop_hash == missing.block_hash(),
            "expected {} and {}", expected_request, tip
        );
        cbfmgr.outbox.drain().for_each(drop);

        // 7. Receive #6.
        let msg = util::cfilters(iter::once(missing)).next().unwrap();
        cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();

        // 8. Expect that 6 to 8 are processed and 7 and 8 come from the cache.
        let mut events = output::test::events(cbfmgr.outbox.drain())
            .filter(|e| matches!(e, Event::FilterProcessed { .. }));

        assert_matches!(
            events.next(),
            Some(Event::FilterProcessed {
                height: 6,
                matched: false,
                cached: false,
                ..
            })
        );
        assert_matches!(
            events.next(),
            Some(Event::FilterProcessed {
                height: 7,
                matched: true,
                cached: true,
                ..
            })
        );
        assert_matches!(
            events.next(),
            Some(Event::FilterProcessed {
                height: 8,
                matched: true,
                cached: true,
                ..
            })
        );
    }

    #[test]
    fn test_partial_cache_hit_overlap_min_max() {
        // Tip           7
        // Cache   *  6  7  *
        // Rescan  5  6  7  8
        // Request 5  *  *  8
        let cache_range = 6..=7;
        let rescan_range = 5..=8;
        let _cache_hits = [6, 7];
        let expected_requests = [5, 8];

        nakamoto_test::logger::init(log::Level::Debug);

        let mut rng = fastrand::Rng::new();
        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let birth: u64 = *cache_range.start();
        let best: u64 = *cache_range.end();

        let time = LocalTime::now();
        let (mut cbfmgr, mut tree, chain) =
            util::setup(network, best, DEFAULT_FILTER_CACHE_SIZE, time);
        let (watch, _) = gen::watchlist(birth, chain.iter());

        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );

        // 1. Populate the cache from heights 5 to 8.
        cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Included(best),
            watch.clone(),
            &tree,
        );

        for msg in util::cfilters(chain.iter().take(best as usize + 1)) {
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }
        assert_eq!(cbfmgr.rescan.cache.start(), Some(birth));
        assert_eq!(cbfmgr.rescan.cache.end(), Some(best));

        // 2. Advance the block header chain to 9.
        let extent = rescan_range.end() - cache_range.end();
        let (suffix, _tip) = util::extend(&mut tree, extent as usize, &time, &mut rng);
        assert_eq!(tree.height(), *rescan_range.end());

        // 3. Advance the filter header chain to 9.
        cbfmgr.sync(&tree);

        let (_, parent) = cbfmgr.filters.tip();
        let cfheaders = util::cfheaders(*parent, &suffix);

        cbfmgr
            .received_cfheaders(&remote, cfheaders, &tree)
            .unwrap();
        assert_eq!(cbfmgr.filters.height(), *rescan_range.end());

        // 4. Make sure there's nothing in the outbox.
        cbfmgr.outbox.drain().for_each(drop);

        // 5. Trigger a rescan for the new range 7 to 9
        let matched = cbfmgr.rescan(
            rescan_range.start_bound().cloned(),
            rescan_range.end_bound().cloned(),
            watch,
            &tree,
        );
        assert_eq!(matched, vec![]);

        let mut msgs = output::test::messages_from(&mut cbfmgr.outbox, &remote);

        // TODO: Test that there are no other requests.
        for expected in expected_requests {
            let hash = tree.get_block_by_height(expected).unwrap().block_hash();

            assert_matches!(
                msgs.next(),
                Some(NetworkMessage::GetCFilters(GetCFilters {
                    start_height,
                    stop_hash,
                    ..
                })) if stop_hash == hash && start_height as Height == expected
            );
        }
    }

    #[test]
    fn test_full_cache_hit() {
        // Cache   [5, 6, 7, 8]
        // Rescan   * [6, 7] *
    }

    #[test]
    fn test_partial_cache_hit_with_gaps() {
        // Cache   *  6  *  8  *
        // Rescan  5  6  7  8  9
        // Request 5  *  7  *  9

        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let birth: u64 = 5;
        let best: u64 = 9;

        let time = LocalTime::now();
        let (mut cbfmgr, tree, chain) = util::setup(network, best, DEFAULT_FILTER_CACHE_SIZE, time);
        let (watch, _) = gen::watchlist(birth, chain.iter());

        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );

        // 1. Populate the cache with height 6 and 8.
        for height in [6, 8] {
            cbfmgr.rescan(
                Bound::Included(height),
                Bound::Included(height),
                watch.clone(),
                &tree,
            );
            let msg = util::cfilters(iter::once(&chain[height as usize]))
                .next()
                .unwrap();
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }
        // Drain the message queue so we can check what is coming from the next rescan.
        cbfmgr.outbox.drain().for_each(drop);

        // 2. Request range 5 to 9.
        let matched = cbfmgr.rescan(Bound::Included(5), Bound::Included(9), watch, &tree);
        assert!(matched.is_empty());

        // 3. Check for requests only on the heights not in the cache.
        let mut msgs = output::test::messages_from(&mut cbfmgr.outbox, &remote);
        for height in [5, 7, 9] {
            assert_matches!(
                msgs.next(),
                Some(NetworkMessage::GetCFilters(GetCFilters {
                    start_height,
                    ..
                })) if start_height == height
            );
        }
        drop(msgs);

        // 4. Receive some of the missing filters.
        for msg in util::cfilters([&chain[5], &chain[7], &chain[9]].into_iter()) {
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }

        let mut events = output::test::events(cbfmgr.outbox.drain())
            .filter(|e| matches!(e, Event::FilterProcessed { .. }));

        // 5. Check for processed filters, some from the network and some from the cache.
        for (h, c) in [(5, false), (6, true), (7, false), (8, true), (9, false)] {
            assert_matches!(
                events.next(),
                Some(Event::FilterProcessed {
                    height,
                    cached,
                    ..
                }) if height == h && cached == c
            );
        }
    }

    // TODO: Test that we panic if we get filters beyond the allowed range
    // TODO: Test rescan when the filter header chain is not caught up to the start of the range.

    #[test]
    fn test_cache_update_rescan() {
        let mut rng = fastrand::Rng::new();
        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();
        let birth = 11;
        let best = 17;

        let time = LocalTime::now();
        let (mut cbfmgr, tree, chain) = util::setup(network, best, DEFAULT_FILTER_CACHE_SIZE, time);

        // Generate a watchlist and keep track of the matching block heights.
        let (watch, matches, _) = gen::watchlist_rng(birth, chain.iter(), &mut rng);

        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );
        let matched = cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Unbounded,
            watch.clone(),
            &tree,
        );
        assert!(matched.is_empty());

        for msg in util::cfilters(chain.iter().take(best as usize + 1)) {
            cbfmgr.received_cfilter(&remote, msg, &tree).unwrap();
        }
        assert_eq!(cbfmgr.rescan.cache.len(), (best - birth) as usize + 1);
        assert_eq!(cbfmgr.rescan.cache.start(), Some(birth));
        assert_eq!(cbfmgr.rescan.cache.end(), Some(best));
        assert_eq!(cbfmgr.rescan.current, best + 1);

        // After a new rescan with a non-empty watchlist, the scripts are checked against the
        // cached filters.
        let matched = cbfmgr.rescan(
            Bound::Included(birth),
            Bound::Unbounded,
            watch.clone(),
            &tree,
        );

        assert_eq!(matched.len(), matches.len());
        assert_eq!(matched.iter().map(|(h, _)| *h).collect::<Vec<_>>(), matches);
        assert_eq!(cbfmgr.rescan.current, best + 1);
        assert_eq!(cbfmgr.rescan.watch, watch.into_iter().collect());
    }

    /// Test that we re-request all filters after blocks are reverted and eventually
    /// get back in sync.
    #[test]
    fn test_rescan_reorg() {
        let tests: [(
            // Best height.
            Height,
            // Birth height.
            Height,
            // Sync height (height up to which we have processed filters).
            Height,
            // Fork height.
            Height,
            // Fork length.
            usize,
            // Height from which we expect cfheaders to be re-requested.
            Height,
            // Height from which we expect cfilters to be re-requested.
            Height,
        ); 5] = [
            (1, 0, 1, 0, 2, 1, 1),
            (7, 5, 7, 0, 8, 1, 5), // Rescan from scan start
            (7, 2, 7, 3, 8, 4, 4), // Rescan from fork height
            (7, 2, 3, 5, 8, 6, 8), // No rescan
            (7, 7, 7, 3, 8, 4, 7),
        ];
        nakamoto_test::logger::init(log::Level::Debug);

        for (
            best,
            birth,
            sync_height,
            fork_height,
            fork_len,
            cfheader_req_start,
            cfilter_req_start,
        ) in tests
        {
            log::debug!(target: "test", "Test case with birth = {}, height = {}", birth, best);

            assert!(fork_height < best);
            assert!(birth <= best);
            assert!(fork_len > 0);
            assert!(cfilter_req_start >= birth);
            assert!(cfheader_req_start <= cfilter_req_start);

            let mut rng = fastrand::Rng::with_seed(772092983);
            let network = Network::Regtest;
            let remote: PeerId = ([88, 88, 88, 88], 8333).into();

            let time = LocalTime::now();
            let (mut cbfmgr, mut tree, chain) = util::setup(network, best, 0, time);

            // Generate a watchlist and keep track of the matching block heights.
            let (watch, _, _) = gen::watchlist_rng(birth, chain.iter(), &mut rng);

            cbfmgr.initialize(&tree);
            cbfmgr.peer_negotiated(
                remote,
                best,
                REQUIRED_SERVICES,
                Link::Outbound,
                false,
                &tree,
            );
            cbfmgr.rescan(Bound::Included(birth), Bound::Unbounded, watch, &tree);

            log::debug!(target: "test",
                "Chain {:?}",
                tree.iter().map(|(_, b)| b.block_hash()).collect::<Vec<_>>()
            );

            // ... Setup ...

            // First let's catch up the client with filters up to the sync height.
            for filter in util::cfilters(chain.iter().take(sync_height as usize + 1)) {
                cbfmgr.received_cfilter(&remote, filter, &tree).unwrap();
            }
            assert_eq!(cbfmgr.rescan.current, sync_height + 1);
            cbfmgr.outbox.drain().for_each(drop);

            // ... Create a fork ...

            let parent = fork_height;
            let fork = gen::fork(
                tree.get_block_by_height(parent).unwrap(),
                fork_len,
                &mut rng,
            );
            log::debug!(target: "test", "Fork {:?}", &fork.iter().map(|b| b.header).collect::<Vec<_>>());

            // ... Import fork ...

            let (tip, reverted, connected) = assert_matches!(
                tree.import_blocks(fork.iter().map(|b| b.header), &time).unwrap(),
                ImportResult::TipChanged { hash, reverted, connected, .. } => (hash, reverted, connected)
            );

            assert_matches!(reverted.last(), Some((height, _)) if *height == fork_height + 1);

            log::debug!(target: "test",
                "Rollback to {}, stop = {}, length = {}",
                parent,
                tip,
                fork.len()
            );

            // ... Perform rollback ...

            cbfmgr.rollback(fork_height).unwrap();
            cbfmgr.sync(&tree);

            log::debug!(target: "test",
                "Imported {:?}",
                fork.iter().map(|b| b.block_hash()).collect::<Vec<_>>()
            );
            log::debug!(target: "test", "Reverted {:?}", reverted);

            assert!(!reverted.is_empty(), "Blocks should be reverted");
            assert!(!connected.is_empty(), "Blocks should be connected");
            assert!(reverted.len() < connected.len());
            assert_eq!(fork.len(), connected.len());
            assert_eq!(fork.last().map(|b| b.block_hash()), Some(tip));

            // Check that filter headers are requested.
            assert_matches!(
                output::test::messages_from(&mut cbfmgr.outbox, &remote).next().unwrap(),
                NetworkMessage::GetCFHeaders(GetCFHeaders {
                    start_height,
                    stop_hash,
                    ..
                }) if start_height as Height == cfheader_req_start && stop_hash == tip,
                "expected {} and {}", cfheader_req_start, tip
            );

            // Then import them.
            let (_, parent) = cbfmgr.filters.tip();
            let cfheaders = util::cfheaders(*parent, &fork);
            cbfmgr
                .received_cfheaders(&remote, cfheaders, &tree)
                .unwrap();

            // Check that corresponding filters are requested within the scope of the
            // current rescan.
            assert_matches!(
                output::test::messages_from(&mut cbfmgr.outbox, &remote).next().unwrap(),
                NetworkMessage::GetCFilters(GetCFilters {
                    start_height,
                    stop_hash,
                    ..
                }) if start_height as Height == cfilter_req_start && stop_hash == tip,
                "expected {} and {}", cfilter_req_start, tip
            );
        }
    }

    #[quickcheck]
    fn prop_rescan(birth: Height, best: Height, cache: usize) -> quickcheck::TestResult {
        // We don't gain anything by testing longer chains.
        if !(1..16).contains(&best) || birth > best {
            return TestResult::discard();
        }
        log::debug!("-- Test case with birth = {}, best = {} --", birth, best);

        let cache = cache % DEFAULT_FILTER_CACHE_SIZE;
        let mut rng = fastrand::Rng::new();
        let network = Network::Regtest;
        let remote: PeerId = ([88, 88, 88, 88], 8333).into();

        let time = LocalTime::now();
        let (mut cbfmgr, tree, chain) = util::setup(network, best, cache, time);
        let tip = chain.last().block_hash();

        // Generate a watchlist and keep track of the matching block heights.
        let (watch, heights, _) = gen::watchlist_rng(birth, chain.iter(), &mut rng);
        if watch.is_empty() {
            return TestResult::discard();
        }

        cbfmgr.filters.clear().unwrap();
        cbfmgr.initialize(&tree);
        cbfmgr.peer_negotiated(
            remote,
            best,
            REQUIRED_SERVICES,
            Link::Outbound,
            false,
            &tree,
        );
        cbfmgr.rescan(Bound::Included(birth), Bound::Unbounded, watch, &tree);

        let msgs = output::test::messages_from(&mut cbfmgr.outbox, &remote).collect::<Vec<_>>();

        msgs.iter()
            .find(|m| {
                matches!(
                    m,
                    NetworkMessage::GetCFHeaders(GetCFHeaders {
                        start_height,
                        stop_hash,
                        ..
                    }) if *start_height == 1 && stop_hash == &tip
                )
            })
            .unwrap();

        // If the birth height is `0`, we already have the header and can thus request
        // the filter.
        if birth == 0 {
            msgs.iter().find(|m| {
                matches!(
                    m,
                    NetworkMessage::GetCFilters(GetCFilters {
                        start_height,
                        stop_hash,
                        ..
                    }) if *start_height as Height == 0 && stop_hash == &chain.first().block_hash()
                )
            })
            .unwrap();
        }

        let cfheaders = util::cfheaders(FilterHeader::genesis(network), &chain.tail);
        let height = cbfmgr
            .received_cfheaders(&remote, cfheaders, &tree)
            .unwrap();

        assert_eq!(height, best, "The new height is the best height");

        output::test::messages_from(&mut cbfmgr.outbox, &remote)
            .find(|m| {
                // If the birth height is `0`, we've already requested the filter, so start at `1`.
                let start = if birth == 0 { 1 } else { birth };

                matches!(
                    m,
                    NetworkMessage::GetCFilters(GetCFilters {
                        start_height,
                        stop_hash,
                        ..
                    }) if *start_height as Height == start && stop_hash == &tip
                )
            })
            .unwrap();

        output::test::events(cbfmgr.outbox.drain())
            .find(|e| matches!(e, Event::FilterHeadersSynced { height } if height == &best))
            .unwrap();

        // Create and shuffle filters so that they arrive out-of-order.
        let mut filters: Vec<_> = (birth..=best)
            .zip(util::cfilters(chain.iter().skip(birth as usize)))
            .collect();
        rng.shuffle(&mut filters);

        let mut matches = Vec::new();
        for (_, filter) in filters.into_iter() {
            let hashes = cbfmgr.received_cfilter(&remote, filter, &tree).unwrap();

            matches.extend(
                hashes
                    .into_iter()
                    .filter_map(|(_, h)| tree.get_block(&h).map(|(height, _)| height)),
            );
        }

        assert_eq!(
            matches, heights,
            "The blocks requested are the ones that matched"
        );
        quickcheck::TestResult::passed()
    }
}
