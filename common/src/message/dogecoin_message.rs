use std::{io, u32};
use std::io::Read;
use bitcoin::consensus::{Decodable, encode};
use bitcoin::consensus::encode::CheckedData;
use bitcoin::network::message::{CommandString, MAX_MSG_SIZE, NetworkMessage, RawNetworkMessage};
use bitcoin::{BlockHash, BlockHeader, Transaction, VarInt};
use bitcoin_hashes::sha256d;
use crate::params::VERSION_FLAG_AUXPOW;

/// Used to deference the BlockHeaderAuxPow
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DogeCoinNetworkMessage {
    /// Same messages between btc and doge
    Original(NetworkMessage),
    /// Message for BlockHeaderAuxPow
    DogeHeaders(Vec<BlockHeaderAuxPow>)
}

impl From<DogeCoinNetworkMessage> for NetworkMessage {
    fn from(value: DogeCoinNetworkMessage) -> Self {
        match value {
            DogeCoinNetworkMessage::Original(msg) => msg,
            DogeCoinNetworkMessage::DogeHeaders(msg) => {
                NetworkMessage::Headers(msg.into_iter().map(|h|h.into()).collect())
            }
        }
    }
}

impl From<&DogeCoinNetworkMessage> for NetworkMessage {
    fn from(value: &DogeCoinNetworkMessage) -> Self {
        match value {
            DogeCoinNetworkMessage::Original(msg) => msg.clone(),
            DogeCoinNetworkMessage::DogeHeaders(msg) => {
                NetworkMessage::Headers(msg.into_iter().map(|h|h.clone().into()).collect())
            }
        }
    }
}

/// A Network message to deal dogecoin
#[derive(Debug, Clone)]
pub struct DogeCoinRawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: DogeCoinNetworkMessage,
}

impl Decodable for DogeCoinRawNetworkMessage {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode_from_finite_reader(r)?;
        let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
        let raw_payload = CheckedData::consensus_decode_from_finite_reader(r)?.0;

        let mut mem_d = io::Cursor::new(raw_payload);
        let payload = match cmd.as_ref() {
            "version" => DogeCoinNetworkMessage::Original(NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "verack" => DogeCoinNetworkMessage::Original(NetworkMessage::Verack),
            "addr" => DogeCoinNetworkMessage::Original(NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "inv" => DogeCoinNetworkMessage::Original(NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getdata" => DogeCoinNetworkMessage::Original(NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "notfound" => DogeCoinNetworkMessage::Original(NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getblocks" => DogeCoinNetworkMessage::Original(NetworkMessage::GetBlocks(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getheaders" => DogeCoinNetworkMessage::Original(NetworkMessage::GetHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "mempool" => DogeCoinNetworkMessage::Original(NetworkMessage::MemPool),
            "block" => DogeCoinNetworkMessage::Original(NetworkMessage::Block(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "headers" => DogeCoinNetworkMessage::DogeHeaders(
                DogeCoinHeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0
            ),
            "sendheaders" => DogeCoinNetworkMessage::Original(NetworkMessage::SendHeaders),
            "getaddr" => DogeCoinNetworkMessage::Original(NetworkMessage::GetAddr),
            "ping" => DogeCoinNetworkMessage::Original(NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "pong" => DogeCoinNetworkMessage::Original(NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "merkleblock" => DogeCoinNetworkMessage::Original(NetworkMessage::MerkleBlock(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "filterload" => DogeCoinNetworkMessage::Original(NetworkMessage::FilterLoad(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "filteradd" => DogeCoinNetworkMessage::Original(NetworkMessage::FilterAdd(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "filterclear" => DogeCoinNetworkMessage::Original(NetworkMessage::FilterClear),
            "tx" => DogeCoinNetworkMessage::Original(NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getcfilters" => DogeCoinNetworkMessage::Original(NetworkMessage::GetCFilters(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "cfilter" => DogeCoinNetworkMessage::Original(NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getcfheaders" => DogeCoinNetworkMessage::Original(NetworkMessage::GetCFHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "cfheaders" => DogeCoinNetworkMessage::Original(NetworkMessage::CFHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getcfcheckpt" => DogeCoinNetworkMessage::Original(NetworkMessage::GetCFCheckpt(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "cfcheckpt" => DogeCoinNetworkMessage::Original(NetworkMessage::CFCheckpt(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "reject" => DogeCoinNetworkMessage::Original(NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "alert" => DogeCoinNetworkMessage::Original(NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "feefilter" => DogeCoinNetworkMessage::Original(NetworkMessage::FeeFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "sendcmpct" => DogeCoinNetworkMessage::Original(NetworkMessage::SendCmpct(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "cmpctblock" => DogeCoinNetworkMessage::Original(NetworkMessage::CmpctBlock(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "getblocktxn" => DogeCoinNetworkMessage::Original(NetworkMessage::GetBlockTxn(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "blocktxn" => DogeCoinNetworkMessage::Original(NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "wtxidrelay" => DogeCoinNetworkMessage::Original(NetworkMessage::WtxidRelay),
            "addrv2" => DogeCoinNetworkMessage::Original(NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)),
            "sendaddrv2" => DogeCoinNetworkMessage::Original(NetworkMessage::SendAddrV2),
            _ => DogeCoinNetworkMessage::Original(NetworkMessage::Unknown {
                command: cmd,
                payload: mem_d.into_inner(),
            })
        };
        Ok(DogeCoinRawNetworkMessage {
            magic,
            payload,
        })
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

impl From<DogeCoinRawNetworkMessage> for RawNetworkMessage {
    fn from(val: DogeCoinRawNetworkMessage) -> Self {
        match val.payload {
            DogeCoinNetworkMessage::Original(msg) => {
                RawNetworkMessage {
                    magic: val.magic,
                    payload: msg,
                }
            }
            DogeCoinNetworkMessage::DogeHeaders(msg) => {
                let headers = NetworkMessage::Headers(msg.into_iter().map(|h|h.into()).collect());
                RawNetworkMessage{
                    magic:val.magic,
                    payload: headers
                }
            }
        }
    }
}

impl From<&DogeCoinRawNetworkMessage> for RawNetworkMessage {
    fn from(raw_msg: &DogeCoinRawNetworkMessage) -> Self {
        let msg = raw_msg.payload.clone();
        match msg {
            DogeCoinNetworkMessage::Original(msg) => {
                RawNetworkMessage {
                    magic: raw_msg.magic,
                    payload: msg,
                }
            }
            DogeCoinNetworkMessage::DogeHeaders(msg) => {
                let headers = NetworkMessage::Headers(msg.into_iter().map(|h|h.into()).collect());
                RawNetworkMessage{
                    magic:raw_msg.magic,
                    payload: headers
                }
            }
        }
    }
}

struct DogeCoinHeaderDeserializationWrapper(Vec<BlockHeaderAuxPow>);

impl Decodable for DogeCoinHeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            let mut parent_coinbase_tx = None;
            let mut parent_blockhash = None;
            let mut coinbase_merkle_branch_hash = vec![];
            let mut n_index = 0;
            let mut blockchain_merkle_branch_hash = vec![];
            let mut chain_index = 0;
            let mut parent_block_header = None;

            let header: BlockHeader = Decodable::consensus_decode(r)?;

            // if has AuxPow, parse the parent block
            if (header.version & VERSION_FLAG_AUXPOW) != 0{
                parent_coinbase_tx.replace(Transaction::consensus_decode(r)?);

                parent_blockhash.replace(BlockHash::consensus_decode(r)?.as_hash());

                let coinbase_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.. coinbase_merkle_branch_len.0 {
                    coinbase_merkle_branch_hash.push(BlockHash::consensus_decode(r)?.as_hash()) ;
                }
                n_index = u32::consensus_decode(r)?;

                let blockchain_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.. blockchain_merkle_branch_len.0 {
                    blockchain_merkle_branch_hash.push(BlockHash::consensus_decode(r)?.as_hash());
                }
                chain_index = u32::consensus_decode(r)?;

                parent_block_header.replace(BlockHeader::consensus_decode(r)?);
            }

            if u8::consensus_decode(r)? != 0u8 {
                println!("ParseFailed block {}", header.block_hash());
                return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
            }

            ret.push(BlockHeaderAuxPow{
                block_header: header,
                parent_coinbase_tx,
                parent_blockhash,
                coinbase_merkle_branch_hash,
                n_index,
                blockchain_merkle_branch_hash,
                chain_index,
                parent_block_header,
            });
        }
        Ok(DogeCoinHeaderDeserializationWrapper(ret))
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

/// A block header with the aux pow info
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockHeaderAuxPow {
    /// block_header
    pub block_header: BlockHeader,
    /// parent_coinbase_tx
    pub parent_coinbase_tx: Option<Transaction>,
    /// parent_blockhash
    pub parent_blockhash: Option<sha256d::Hash>,
    /// coinbase_merkle_branch_hash
    pub coinbase_merkle_branch_hash: Vec<sha256d::Hash>,
    /// n_index
    pub n_index: u32,
    /// blockchain_merkle_branch_hash
    pub blockchain_merkle_branch_hash: Vec<sha256d::Hash>,
    /// chain_index
    pub chain_index: u32,
    /// parent_block_header
    pub parent_block_header: Option<BlockHeader>,
}

impl From<BlockHeaderAuxPow> for BlockHeader {
    fn from(value: BlockHeaderAuxPow) -> Self {
        BlockHeader{
            ..value.block_header
        }
    }
}