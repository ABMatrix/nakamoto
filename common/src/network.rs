//! Bitcoin peer network. Eg. *Mainnet*.
use std::str::FromStr;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::ServiceFlags;
use bitcoin::{OutPoint, PackedLockTime, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness};
use bitcoin::blockdata::{opcodes, script};
use bitcoin::blockdata::constants::COIN_VALUE;

use bitcoin_hashes::{sha256d, Hash, hex};
use bitcoin_hashes::hex::HexIterator;

use crate::block::Height;
use crate::params::Params;

/// Peer services supported by nakamoto.
#[derive(Debug, Copy, Clone, Default)]
pub enum Services {
    /// Peers with compact filter support.
    #[default]
    All,
    /// Peers with only block support.
    Chain,
}

impl From<Services> for ServiceFlags {
    fn from(value: Services) -> Self {
        match value {
            Services::All => Self::COMPACT_FILTERS | Self::NETWORK,
            Services::Chain => Self::NETWORK,
        }
    }
}

/// Bitcoin peer network.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Network {
    /// Bitcoin Mainnet.
    Mainnet,
    /// Bitcoin Testnet.
    Testnet,
    /// Bitcoin regression test net.
    Regtest,
    /// Bitcoin signet.
    Signet,
    /// Dogecoin Mainnet.
    DOGECOINMAINNET,
    /// Dogecoin Testnet.
    DOGECOINTESTNET,
    /// Dogecoin regression test net.
    DOGECOINREGTEST,
}

impl Default for Network {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "bitcoin" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            "signet" => Ok(Self::Signet),
            "dogecoin_mainnet" => Ok(Self::DOGECOINMAINNET),
            "dogecoin_testnet" => Ok(Self::DOGECOINTESTNET),
            "dogecoin_regtest" => Ok(Self::DOGECOINREGTEST),
            _ => Err(format!("invalid network specified {:?}", s)),
        }
    }
}

impl From<Network> for bitcoin::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
            Network::Signet => Self::Signet,
            _ => unreachable!("should never happened"),
        }
    }
}

impl From<bitcoin::Network> for Network {
    fn from(value: bitcoin::Network) -> Self {
        match value {
            bitcoin::Network::Bitcoin => Self::Mainnet,
            bitcoin::Network::Testnet => Self::Testnet,
            bitcoin::Network::Signet => Self::Signet,
            bitcoin::Network::Regtest => Self::Regtest,
        }
    }
}

impl Network {
    /// Return the default listen port for the network.
    pub fn port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Regtest => 18334,
            Network::Signet => 38333,
            Network::DOGECOINMAINNET => 22556,
            Network::DOGECOINTESTNET => 44556,
            Network::DOGECOINREGTEST => 18444,
        }
    }

    /// Blockchain checkpoints.
    pub fn checkpoints(&self) -> Box<dyn Iterator<Item=(Height, BlockHash)>> {
        use crate::block::checkpoints;

        let iter = match self {
            Network::Mainnet => checkpoints::MAINNET,
            Network::Testnet => checkpoints::TESTNET,
            Network::Regtest | Network::DOGECOINREGTEST => checkpoints::REGTEST,
            Network::Signet => checkpoints::SIGNET,
            Network::DOGECOINMAINNET => checkpoints::DOGECOINMAINNET,
            Network::DOGECOINTESTNET => checkpoints::DOGECOINTESTNET,
        }
            .iter()
            .cloned()
            .map(|(height, hash)| {
                let hash = BlockHash::from_hex(hash).unwrap();
                (height, hash)
            });

        Box::new(iter)
    }

    /// Return the short string representation of this network.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
            Network::DOGECOINMAINNET => "dogecoin_mainnet",
            Network::DOGECOINTESTNET => "dogecoin_testnet",
            Network::DOGECOINREGTEST => "dogecoin_regtest",
        }
    }

    /// DNS seeds. Used to bootstrap the client's address book.
    pub fn seeds(&self) -> &[&str] {
        match self {
            Network::Mainnet => &[
                "seed.bitcoin.sipa.be",          // Pieter Wuille
                "dnsseed.bluematt.me",           // Matt Corallo
                "dnsseed.bitcoin.dashjr.org",    // Luke Dashjr
                "seed.bitcoinstats.com",         // Christian Decker
                "seed.bitcoin.jonasschnelli.ch", // Jonas Schnelli
                "seed.btc.petertodd.org",        // Peter Todd
                "seed.bitcoin.sprovoost.nl",     // Sjors Provoost
                "dnsseed.emzy.de",               // Stephan Oeste
                "seed.bitcoin.wiz.biz",          // Jason Maurice
                "seed.cloudhead.io",             // Alexis Sellier
            ],
            Network::Testnet => &[
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ],
            Network::Regtest | Network::DOGECOINREGTEST => &[], // No seeds
            Network::Signet => &["seed.signet.bitcoin.sprovoost.nl"],
            Network::DOGECOINMAINNET => &[
                "multidoge.org",
                "seed.multidoge.org",
                "seed2.multidoge.org",
            ],
            Network::DOGECOINTESTNET => &[
                // "45.63.86.162",
                // "44.211.225.142",
                // "94.62.224.95",
                // "198.58.102.18",
                // "139.167.11.99",
                // "104.237.131.138",
                "node.jrn.me.uk",
                "jrn.me.uk",
                "testseed.jrn.me.uk",
                "37.27.63.117",
                "185.232.70.226",
                "45.77.185.15",
            ],
        }
    }
}

impl Network {
    /// Get the genesis block header.
    ///
    /// ```
    /// use nakamoto_common::network::Network;
    ///
    /// let network = Network::Mainnet;
    /// let genesis = network.genesis();
    ///
    /// assert_eq!(network.genesis_hash(), genesis.block_hash());
    /// ```
    pub fn genesis(&self) -> BlockHeader {
        self.genesis_block().header
    }

    /// Get the genesis block.
    pub fn genesis_block(&self) -> Block {
        use bitcoin::blockdata::constants;
        match self {
            Network::DOGECOINMAINNET | Network::DOGECOINTESTNET | Network::DOGECOINREGTEST => {
                self.dogecoin_genesis_block()
            }
            _ => constants::genesis_block((*self).into()),
        }
    }

    /// Get the dogecoin genesis block.
    pub fn dogecoin_genesis_block(&self) -> Block {
        let dogecoin_genesis_tx = || -> Transaction {
            // Base
            let mut ret = Transaction {
                version: 1,
                lock_time: PackedLockTime::ZERO,
                input: vec![],
                output: vec![],
            };

            // Inputs
            let in_script = script::Builder::new().push_scriptint(486604799)
                .push_scriptint(4)
                .push_slice(b"Nintondo")
                .into_script();
            ret.input.push(TxIn {
                previous_output: OutPoint::null(),
                script_sig: in_script,
                sequence: Sequence::MAX,
                witness: Witness::default(),
            });

            // Outputs
            let script_bytes: Result<Vec<u8>, hex::Error> =
                HexIterator::new("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9").unwrap()
                    .collect();
            let out_script = script::Builder::new()
                .push_slice(script_bytes.unwrap().as_slice())
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script();
            ret.output.push(TxOut {
                value: 88 * COIN_VALUE,
                script_pubkey: out_script
            });

            // end
            ret
        };
        let genesis_tx =  dogecoin_genesis_tx();
        let hash: sha256d::Hash = genesis_tx.txid().into();
        let merkle_root: TxMerkleNode = hash.into();
        match self {
            Network::DOGECOINMAINNET => {
                Block {
                    header: BlockHeader {
                        version: 1,
                        prev_blockhash: Hash::all_zeros(),
                        merkle_root,
                        time: 1386325540,
                        bits: 0x1e0ffff0,
                        nonce: 99943,
                    },
                    txdata: vec![genesis_tx],
                }
            }
            Network::DOGECOINTESTNET => {
                Block {
                    header: BlockHeader {
                        version: 1,
                        prev_blockhash: Hash::all_zeros(),
                        merkle_root,
                        time: 1391503289,
                        bits: 0x1e0ffff0,
                        nonce: 997879,
                    },
                    txdata: vec![genesis_tx],
                }
            }
            Network::DOGECOINREGTEST => {
                Block {
                    header: BlockHeader {
                        version: 1,
                        prev_blockhash: Hash::all_zeros(),
                        merkle_root,
                        time: 1296688602,
                        bits: 0x207fffff,
                        nonce: 2,
                    },
                    txdata: vec![genesis_tx],
                }
            }
            _ => unreachable!("should never happened"),
        }
    }

    /// Get the hash of the genesis block of this network.
    pub fn genesis_hash(&self) -> BlockHash {
        use crate::block::genesis;

        let hash = match self {
            Self::Mainnet => genesis::MAINNET,
            Self::Testnet => genesis::TESTNET,
            Self::Regtest => genesis::REGTEST,
            Self::Signet => genesis::SIGNET,
            Self::DOGECOINMAINNET => genesis::DOGECOINMAINNET,
            Self::DOGECOINTESTNET => genesis::DOGECOINTESTNET,
            Self::DOGECOINREGTEST => genesis::DOGECOINREGTEST,
        };
        BlockHash::from_hash(
            sha256d::Hash::from_slice(hash)
                .expect("the genesis hash has the right number of bytes"),
        )
    }

    /// Get the consensus parameters for this network.
    pub fn params(&self) -> Params {
        Params::new(*self)
    }

    /// Get the network magic number for this network.
    pub fn magic(&self) -> u32 {
        match self {
            Network::DOGECOINMAINNET => 0xC0C0C0C0,
            Network::DOGECOINTESTNET => 0xDCB7C1FC,
            Network::DOGECOINREGTEST => 0xDAB5BFFA,
            _ => bitcoin::Network::from(*self).magic(),
        }
    }
}
