use std::io;
use std::io::Read;
use nakamoto_common::bitcoin::consensus::{Decodable, encode};
use nakamoto_common::bitcoin::consensus::encode::CheckedData;
use nakamoto_common::bitcoin::network::message::{CommandString, MAX_MSG_SIZE, NetworkMessage, RawNetworkMessage};
use nakamoto_common::bitcoin::{BlockHash, BlockHeader, Transaction, VarInt};

/// VERSION_AUXPOW
const VERSION_FLAG_AUXPOW: i32 = 1 << 8;

/// A Network message to deal dogecoin
pub struct DogeCoinRawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage,
}

impl Decodable for DogeCoinRawNetworkMessage {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode_from_finite_reader(r)?;
        let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
        let raw_payload = CheckedData::consensus_decode_from_finite_reader(r)?.0;

        let mut mem_d = io::Cursor::new(raw_payload);
        let payload = match cmd.as_ref() {
            "version" => NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "verack" => NetworkMessage::Verack,
            "addr" => NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "inv" => NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getdata" => NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getblocks" => NetworkMessage::GetBlocks(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getheaders" => NetworkMessage::GetHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "mempool" => NetworkMessage::MemPool,
            "block" => NetworkMessage::Block(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "headers" => NetworkMessage::Headers(
                DogeCoinHeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping" => NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "pong" => NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "merkleblock" => NetworkMessage::MerkleBlock(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "filterload" => NetworkMessage::FilterLoad(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "filteradd" => NetworkMessage::FilterAdd(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "filterclear" => NetworkMessage::FilterClear,
            "tx" => NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfilters" => NetworkMessage::GetCFilters(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "cfilter" => NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfheaders" => NetworkMessage::GetCFHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "cfheaders" => NetworkMessage::CFHeaders(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "cfcheckpt" => NetworkMessage::CFCheckpt(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "reject" => NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "alert" => NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "feefilter" => NetworkMessage::FeeFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "sendcmpct" => NetworkMessage::SendCmpct(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "cmpctblock" => NetworkMessage::CmpctBlock(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getblocktxn" => NetworkMessage::GetBlockTxn(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "blocktxn" => NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "addrv2" => NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            _ => NetworkMessage::Unknown {
                command: cmd,
                payload: mem_d.into_inner(),
            }
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
        RawNetworkMessage {
            magic: val.magic,
            payload: val.payload,
        }
    }
}

struct DogeCoinHeaderDeserializationWrapper(Vec<BlockHeader>);

impl Decodable for DogeCoinHeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            let header: BlockHeader = Decodable::consensus_decode(r)?;

            // if has AuxPow, parse the parent block
            if (header.version & VERSION_FLAG_AUXPOW) != 0{
                let _parent_coinbase_tx = Transaction::consensus_decode(r)?;

                let _parent_blockhash = BlockHash::consensus_decode(r)?;

                let _coinbase_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.. _coinbase_merkle_branch_len.0 {
                    let _coinbase_merkle_branch_hash = BlockHash::consensus_decode(r)?;
                }
                let _coinbase_merkle_branch_size_mask = i32::consensus_decode(r)?;

                let _blockchain_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.. _blockchain_merkle_branch_len.0 {
                    let _blockchain_merkle_branch_hash = BlockHash::consensus_decode(r)?;
                }
                let _blockchain_merkle_branch_size_mask = i32::consensus_decode(r)?;

                let _parent_block_header = BlockHeader::consensus_decode(r)?;
            }

            if u8::consensus_decode(r)? != 0u8 {
                println!("ParseFailed block {}", header.block_hash());
                return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
            }

            ret.push(header);
        }
        Ok(DogeCoinHeaderDeserializationWrapper(ret))
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}