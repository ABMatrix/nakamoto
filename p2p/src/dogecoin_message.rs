use std::{i32, io, u32};
use std::io::Read;
use nakamoto_common::bitcoin::consensus::{Decodable, encode, serialize};
use nakamoto_common::bitcoin::consensus::encode::CheckedData;
use nakamoto_common::bitcoin::network::message::{CommandString, MAX_MSG_SIZE, NetworkMessage, RawNetworkMessage};
use nakamoto_common::bitcoin::{BlockHash, BlockHeader, Transaction, util, VarInt};
use nakamoto_common::bitcoin::util::uint::Uint256;
use nakamoto_common::bitcoin_hashes::{Hash, HashEngine, sha256d};
use nakamoto_common::network::Network;
use nakamoto_common::params::Params;
use nakamoto_common::scrypt;

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
            "headers" => {
                let mut headers = vec![];
                let aux_headers = DogeCoinHeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0;
                let params = DogeCoinRawNetworkMessage::from_magic(magic).unwrap().params();
                for aux_header in aux_headers {
                    if aux_header.aux.is_none() {
                        // validate pow
                        aux_header.validate_pow().map_err(|_|encode::Error::ParseFailed("validate_pow failed"))?;
                        headers.push(aux_header.block_header)
                    } else {
                        // validate aux and pow
                        aux_header.check_aux(&params).map_err(|_| encode::Error::ParseFailed("check_aux failed"))?;
                        aux_header.validate_pow().map_err(|_| encode::Error::ParseFailed("validate_pow failed"))?;
                        headers.push(aux_header.block_header)
                    }
                }
                NetworkMessage::Headers(headers)
            }
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

impl DogeCoinRawNetworkMessage {
    fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xC0C0C0C0 => Some(Network::DOGECOINMAINNET),
            0xDCB7C1FC => Some(Network::DOGECOINTESTNET),
            0xDAB5BFFA => Some(Network::DOGECOINREGTEST),
            _ => None
        }
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

struct DogeCoinHeaderDeserializationWrapper(Vec<BlockHeaderAuxPow>);

impl Decodable for DogeCoinHeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut rets = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            let mut coinbase_merkle_branch_hashes = vec![];
            let mut blockchain_merkle_branch_hashes = vec![];
            let header: BlockHeader = Decodable::consensus_decode(r)?;

            // if has AuxPow, parse the parent block
            let ret = if (header.version & VERSION_FLAG_AUXPOW) != 0 {
                let parent_coinbase_tx = Transaction::consensus_decode(r)?;

                let parent_blockhash = BlockHash::consensus_decode(r)?.as_hash();

                let _coinbase_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.._coinbase_merkle_branch_len.0 {
                    coinbase_merkle_branch_hashes.push(BlockHash::consensus_decode(r)?.as_hash());
                }
                let n_index = i32::consensus_decode(r)?;

                let _blockchain_merkle_branch_len = VarInt::consensus_decode(r)?;
                for _ in 0.._blockchain_merkle_branch_len.0 {
                    blockchain_merkle_branch_hashes.push(BlockHash::consensus_decode(r)?.as_hash());
                }
                let chain_index = i32::consensus_decode(r)?;

                let parent_block_header = BlockHeader::consensus_decode(r)?;

                BlockHeaderAuxPow {
                    block_header: header,
                    aux: Some(
                        Aux {
                            parent_coinbase_tx,
                            parent_blockhash,
                            coinbase_merkle_branch_hashes,
                            n_index,
                            blockchain_merkle_branch_hashes,
                            chain_index,
                            parent_block_header,
                        }
                    ),
                }
            } else {
                BlockHeaderAuxPow {
                    block_header: header,
                    aux: None,
                }
            };

            if u8::consensus_decode(r)? != 0u8 {
                println!("ParseFailed block {}", header.block_hash());
                return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
            }

            rets.push(ret);
        }
        Ok(DogeCoinHeaderDeserializationWrapper(rets))
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

/// A block header with the aux pow info
#[derive(Debug)]
struct BlockHeaderAuxPow {
    /// The block header
    block_header: BlockHeader,
    /// The detail of AuxPow
    aux: Option<Aux>,
}

impl Decodable for BlockHeaderAuxPow {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut coinbase_merkle_branch_hashes = vec![];
        let mut blockchain_merkle_branch_hashes = vec![];
        let header: BlockHeader = Decodable::consensus_decode(r)?;

        // if has AuxPow, parse the parent block
        let ret = if (header.version & VERSION_FLAG_AUXPOW) != 0 {
            let parent_coinbase_tx = Transaction::consensus_decode(r)?;
            let parent_blockhash = BlockHash::consensus_decode(r)?.as_hash();
            let _coinbase_merkle_branch_len = VarInt::consensus_decode(r)?;
            for _ in 0.._coinbase_merkle_branch_len.0 {
                coinbase_merkle_branch_hashes.push(BlockHash::consensus_decode(r)?.as_hash());
            }

            let n_index = i32::consensus_decode(r)?;

            let _blockchain_merkle_branch_len = VarInt::consensus_decode(r)?;
            for _ in 0.._blockchain_merkle_branch_len.0 {
                blockchain_merkle_branch_hashes.push(BlockHash::consensus_decode(r)?.as_hash());
            }

            let chain_index = i32::consensus_decode(r)?;

            let parent_block_header = BlockHeader::consensus_decode(r)?;

            BlockHeaderAuxPow {
                block_header: header,
                aux: Some(
                    Aux {
                        parent_coinbase_tx,
                        parent_blockhash,
                        coinbase_merkle_branch_hashes,
                        n_index,
                        blockchain_merkle_branch_hashes,
                        chain_index,
                        parent_block_header,
                    }
                ),
            }
        } else {
            BlockHeaderAuxPow {
                block_header: header,
                aux: None,
            }
        };

        Ok(ret)
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}


///  AuxPow
#[derive(Debug, Clone)]
struct Aux {
    /// parent_coinbase_tx
    parent_coinbase_tx: Transaction,
    /// parent_blockhash
    #[allow(dead_code)]
    parent_blockhash: sha256d::Hash,
    /// coinbase_merkle_branch_hashes
    coinbase_merkle_branch_hashes: Vec<sha256d::Hash>,
    /// n_index
    n_index: i32,
    /// blockchain_merkle_branch_hashes
    blockchain_merkle_branch_hashes: Vec<sha256d::Hash>,
    /// chain_index
    chain_index: i32,
    /// parent_block_header
    parent_block_header: BlockHeader,
}

impl BlockHeaderAuxPow {
    const PCH_MERGED_MINING_HEADER: [u8; 4] = [0xFA, 0xBE, b'm', b'm'];

    fn validate_pow(&self) -> Result<(), util::Error> {
        // target will be checked later

        let header_buf = if let Some(aux_pow) = &self.aux {
            serialize(&aux_pow.parent_block_header)
        } else {
            serialize(&self.block_header)
        };
        let mut pow_hash_buf = [0u8; 32];
        let params = scrypt::Params::new(10, 1, 1, 32).unwrap();
        scrypt::scrypt(&header_buf, &header_buf, &params, &mut pow_hash_buf).unwrap();
        let pow_hash = sha256d::Hash::from_slice(&pow_hash_buf).unwrap();
        let mut ret = [0u64; 4];
        Self::bytes_to_u64_slice_le(pow_hash.as_inner(), &mut ret);
        let hash = Uint256(ret);

        if hash <= self.block_header.target() { Ok(()) } else { Err(util::Error::BlockBadProofOfWork) }
    }

    fn check_aux(&self, params: &Params) -> Result<(), util::Error> {
        let aux = self.aux.clone().unwrap();
        let chain_id = self.block_header.version >> 16;
        let parent_chain_id = aux.parent_block_header.version >> 16;

        if (aux.n_index != 0)
            || (params.doge_strict_chain_id() && parent_chain_id == chain_id)
            || aux.blockchain_merkle_branch_hashes.len() > 30
        {
            return Err(util::Error::BlockBadProofOfWork);
        }

        let root_hash = Self::check_merkle_branch(
            self.block_header.block_hash().as_hash(),
            &aux.blockchain_merkle_branch_hashes,
            aux.chain_index,
        );

        let mut root_hash_bytes = root_hash.into_inner();
        root_hash_bytes.reverse();

        if Self::check_merkle_branch(
            aux.parent_coinbase_tx.txid().as_hash(),
            &aux.coinbase_merkle_branch_hashes,
            aux.n_index,
        ) != aux.parent_block_header.merkle_root.as_hash() {
            return Err(util::Error::BlockBadProofOfWork);
        }

        let tx_script = aux.parent_coinbase_tx.input[0].script_sig.clone();
        let pc_head = Self::find_subsequence(tx_script.as_ref(), &Self::PCH_MERGED_MINING_HEADER);
        let pc = Self::find_subsequence(tx_script.as_ref(), &root_hash_bytes);
        if pc.is_none() {
            return Err(util::Error::BlockBadProofOfWork); // "Aux POW missing chain merkle root in parent coinbase"
        }

        let mut pc = pc.unwrap();
        if let Some(pc_head_pos) = pc_head {
            if Self::find_subsequence(&tx_script[pc_head_pos + 1..], &Self::PCH_MERGED_MINING_HEADER).is_some() {
                return Err(util::Error::BlockBadProofOfWork); // "Multiple merged mining headers in coinbase"
            }

            if pc != pc_head_pos + Self::PCH_MERGED_MINING_HEADER.len() {
                return Err(util::Error::BlockBadProofOfWork); // "Merged mining header is not just before chain merkle root"
            }
        } else if pc > 20 {
            return Err(util::Error::BlockBadProofOfWork); // "Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase"
        }


        pc += root_hash_bytes.len();
        if tx_script.len() < pc + 8 {
            return Err(util::Error::BlockBadProofOfWork); // "Aux POW missing chain merkle tree size and nonce in parent coinbase"
        }

        let n_size = u32::from_le_bytes(
            tx_script[pc..pc + 4]
                .try_into()
                .map_err(|_| util::Error::BlockBadProofOfWork)?,
        );

        let merkle_height = aux.blockchain_merkle_branch_hashes.len();

        if n_size != (1u32 << merkle_height) {
            return Err(util::Error::BlockBadProofOfWork); // "Aux POW merkle branch size does not match parent coinbase"
        }

        let n_nonce = u32::from_le_bytes(
            tx_script[pc + 4..pc + 8]
                .try_into()
                .map_err(|_| util::Error::BlockBadProofOfWork)?,
        );

        if aux.chain_index as u32 != Self::get_expected_index(n_nonce, chain_id as u32, merkle_height as u32) {
            return Err(util::Error::BlockBadProofOfWork); // "Aux POW wrong index"
        }

        Ok(())
    }

    fn get_expected_index(n_nonce: u32, chain_id: u32, merkle_height: u32) -> u32 {
        let mut rand = n_nonce;
        rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
        rand = rand.wrapping_add(chain_id);
        rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
        rand % (1u32 << merkle_height)
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    fn check_merkle_branch(
        mut block_hash: sha256d::Hash,
        merkle_branch: &Vec<sha256d::Hash>,
        mut n_index: i32,
    ) -> sha256d::Hash {
        if n_index == -1 {
            return sha256d::Hash::from_slice(&[0; 32]).unwrap();
        }

        for branch_hash in merkle_branch {
            if n_index & 1 == 0 {
                let mut engine = sha256d::Hash::engine();
                engine.input(block_hash.as_ref());
                engine.input(branch_hash.as_ref());
                block_hash = sha256d::Hash::from_engine(engine);
            } else {
                let mut engine = sha256d::Hash::engine();
                engine.input(branch_hash.as_ref());
                engine.input(block_hash.as_ref());
                block_hash = sha256d::Hash::from_engine(engine);
            }
            n_index >>= 1;
        }
        block_hash
    }

    fn bytes_to_u64_slice_le(input: &[u8], output: &mut [u64]) {
        assert!(input.len() >= output.len() * 8, "Input data is too short");

        for (i, chunk) in input.chunks(8).enumerate().take(output.len()) {
            output[i] = u64::from_le_bytes(chunk.try_into().expect("Chunk size must be 8 bytes"));
        }
    }
}

#[cfg(test)]
mod test {
    use nakamoto_common::bitcoin::consensus::encode;
    use nakamoto_common::bitcoin_hashes::hex::FromHex;
    use nakamoto_common::network::Network;
    use crate::dogecoin_message::BlockHeaderAuxPow;

    #[test]
    fn test_aux_header() {
        let aux_header_buf = Vec::from_hex("020162005adc85626e3c36d8e65de509f0a77ffbe856a68402f5689eda3e93594e216eede232ad42c0cbe2792622cf70b982ce940ce8d5b2251275c71c12c56c8456e5f8208b4654d381031b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3803d81a0afabe6d6d96c91675522fb38782b9a2abc1a404648f0e0c2493f2a269dc994da6d4c36d6d40000000000000005b8b05094e000000ffffffff0100f2052a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000e1627671123a1355decccf343a3299c236dd305af4a2473a8a340200000000000000000000066201f4891fc87ea955b7081c3568ec5043b7b2d6ad95e4c818e67987e841db266c4127661ba7d68c453b449868e6135a6ac0d9351a3e40d7dd58767531de67ee31284c19194806e9c00943e05a9d1a79e17fa0c9b79bef9027ad2ca0bdf99eabfe2d8f99be8b35640357d1af6ec9884840d0a9d91dbac1a8334df680016151fff7be6318b98f6decf870b980433c69be97f83ce72ff90f4a1e0236f7bd622eb69b91ec90c8b1ed417d8844fadee53245f60fda029b1175dccf99d26eb5e3de7338000000020000009143a4e3da8a8720eacaa579c803a9e7cc3e0d403bacdd45d5d3b1eed00c711051c0e41c72140e882780e4d6a2df66cc06aaa6dd5b82f6a42e5d52ee61dadc1a208b465483cb011b4c116601").unwrap();
        let (aux_header, _) = encode::deserialize_partial::<BlockHeaderAuxPow>(&aux_header_buf).unwrap();
        let params = Network::DOGECOINTESTNET.params();
        assert!(aux_header.aux.is_some());
        if aux_header.aux.is_some() {
            assert!(aux_header.check_aux(&params).is_ok());
        }
        assert!(aux_header.validate_pow().is_ok());

        let no_aux_header_buf = Vec::from_hex("0200620019f85af5e1ac971c09fe9f4ec53309192c46f13b6ffb0b55289ab4ac2ec40ddd1ccf0e1b1f7a2319c3e6850d2ab77ec83e5e4c55a75bb8613dc5f74e9f2c8cf8d863e053009e061e00111651").unwrap();
        let (no_aux_header, _) = encode::deserialize_partial::<BlockHeaderAuxPow>(&no_aux_header_buf).unwrap();
        let params = Network::DOGECOINTESTNET.params();
        assert!(no_aux_header.aux.is_none());
        if no_aux_header.aux.is_some() {
            assert!(aux_header.check_aux(&params).is_ok());
        }
        assert!(no_aux_header.validate_pow().is_ok());
    }
}