#![allow(missing_docs)]
use std::path::Path;

use bincode::Options;

use nakamoto_common::bitcoin::consensus::encode::{Decodable, Encodable};

use nakamoto_common::bitcoin::consensus::serialize;
use nakamoto_common::block::store::{Error, Store};
use nakamoto_common::block::Height;
use nakamoto_common::block::BlockHeader;
use serde::{Deserialize, Serialize};

pub type Bytes = Vec<u8>;
pub type FullHash = [u8; 32];
const HASH_LEN: usize = 32;

static DB_VERSION: u32 = 2;

pub fn full_hash(hash: &[u8]) -> FullHash {
        //*array_ref![hash, 0, HASH_LEN]

    let mut array = [0u8; HASH_LEN];
    if hash.len() > 32 {
        array.copy_from_slice(&hash[0..32]);
    } else {
        array[..hash.len()].copy_from_slice(hash);
    }
    array
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DBRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct ScanIterator<'a> {
    prefix: Vec<u8>,
    iter: rocksdb::DBIterator<'a>,
    done: bool,
}

impl<'a> Iterator for ScanIterator<'a> {
    type Item = DBRow;

    fn next(&mut self) -> Option<DBRow> {
        if self.done {
            return None;
        }
        let (key, value) = self.iter.next().map(Result::ok)??;
        if !key.starts_with(&self.prefix) {
            self.done = true;
            return None;
        }
        Some(DBRow {
            key: key.to_vec(),
            value: unseal_data(value.to_vec()),
        })
    }
}

pub struct ReverseScanIterator<'a> {
    prefix: Vec<u8>,
    iter: rocksdb::DBRawIterator<'a>,
    done: bool,
}

impl<'a> Iterator for ReverseScanIterator<'a> {
    type Item = DBRow;

    fn next(&mut self) -> Option<DBRow> {
        if self.done || !self.iter.valid() {
            return None;
        }

        let key = self.iter.key().unwrap();
        if !key.starts_with(&self.prefix) {
            self.done = true;
            return None;
        }

        let row = DBRow {
            key: key.into(),
            value: unseal_data(self.iter.value().unwrap().to_vec()),
        };

        self.iter.prev();

        Some(row)
    }
}

#[derive(Debug)]
pub struct DB {
    db: rocksdb::DB,
}

#[derive(Copy, Clone, Debug)]
pub enum DBFlush {
    Disable,
    Enable,
}

#[allow(dead_code)]
impl DB {
    pub fn open(path: &Path) -> DB {
        let db = DB {
            db: open_raw_db(path),
        };
        db.verify_compatibility();
        db
    }

    pub fn full_compaction(&self) {
        // TODO: make sure this doesn't fail silently
        log::info!(target: "spv", "starting full compaction on {:?}", self.db);
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        log::info!(target: "spv", "finished full compaction on {:?}", self.db);
    }

    pub fn enable_auto_compaction(&self) {
        let opts = [("disable_auto_compactions", "false")];
        self.db.set_options(&opts).unwrap();
    }

    pub fn raw_iterator(&self) -> rocksdb::DBRawIterator {
        self.db.raw_iterator()
    }

    pub fn iter_scan(&self, prefix: &[u8]) -> ScanIterator {
        ScanIterator {
            prefix: prefix.to_vec(),
            iter: self.db.prefix_iterator(prefix),
            done: false,
        }
    }

    pub fn iter_scan_from(&self, prefix: &[u8], start_at: &[u8]) -> ScanIterator {
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            start_at,
            rocksdb::Direction::Forward,
        ));
        ScanIterator {
            prefix: prefix.to_vec(),
            iter,
            done: false,
        }
    }

    pub fn iter_scan_reverse(&self, prefix: &[u8], prefix_max: &[u8]) -> ReverseScanIterator {
        let mut iter = self.db.raw_iterator();
        iter.seek_for_prev(prefix_max);

        ReverseScanIterator {
            prefix: prefix.to_vec(),
            iter,
            done: false,
        }
    }

    pub fn write(&self, mut rows: Vec<DBRow>, flush: DBFlush) {
        log::info!(target: "spv",
            "writing {} rows to {:?}, flush={:?}",
            rows.len(),
            self.db,
            flush
        );
        rows.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let mut batch = rocksdb::WriteBatch::default();
        for row in rows {
            batch.put(&row.key, seal_data(row.value));
        }
        let do_flush = match flush {
            DBFlush::Enable => true,
            DBFlush::Disable => false,
        };
        let mut opts = rocksdb::WriteOptions::new();
        opts.set_sync(do_flush);
        opts.disable_wal(!do_flush);
        self.db.write_opt(batch, &opts).unwrap();
    }

    pub fn flush(&self) {
        self.db.flush().unwrap();
    }

    pub fn put(&self, key: &[u8], value: &[u8]) {
        self.db.put(key, seal_data(value.to_vec())).unwrap();
    }

    pub fn put_sync(&self, key: &[u8], value: &[u8]) {
        let mut opts = rocksdb::WriteOptions::new();
        opts.set_sync(true);
        self.db
            .put_opt(key, seal_data(value.to_vec()), &opts)
            .unwrap();
    }

    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.db.get(key).unwrap().map(|v| unseal_data(v))
    }

    fn verify_compatibility(&self) {
        let compatibility_bytes = serialize_little(&DB_VERSION).unwrap();

        // if config.light_mode {
        //     compatibility_bytes.push(1);
        // }

        match self.get(b"V") {
            None => self.put(b"V", &compatibility_bytes),
            Some(ref x) if x != &compatibility_bytes => {
                panic!("Incompatible database found. Please reindex.")
            }
            Some(_) => (),
        }
    }
}

pub fn open_raw_db<T: rocksdb::ThreadMode>(path: &Path) -> rocksdb::DBWithThreadMode<T> {
    log::info!(target: "spv", "opening DB at {:?}", path);
    let mut db_opts = rocksdb::Options::default();
    db_opts.create_if_missing(true);
    db_opts.set_max_open_files(100_00); // TODO: make sure to `ulimit -n` this process correctly
    db_opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
    db_opts.set_compression_type(rocksdb::DBCompressionType::None);
    db_opts.set_target_file_size_base(0x16000000);
    db_opts.set_write_buffer_size(0x16000000);
    db_opts.set_disable_auto_compactions(true); // for initial bulk load

    // db_opts.set_advise_random_on_open(???);
    db_opts.set_compaction_readahead_size(1 << 20);
    db_opts.increase_parallelism(2);

    // let mut block_opts = rocksdb::BlockBasedOptions::default();
    // block_opts.set_block_size(???);

    rocksdb::DBWithThreadMode::<T>::open(&db_opts, path).expect("failed to open RocksDB")
}

pub fn seal_data(value: Vec<u8>) -> Vec<u8> {
    value //sgx_bool_registration_tool::sealing(value).unwrap()
}

pub fn unseal_data(value: Vec<u8>) -> Vec<u8> {
    value //sgx_bool_registration_tool::unsealing(value).unwrap()
}

#[inline]
fn options() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .with_no_limit()
        .allow_trailing_bytes()
}

#[inline]
fn little_endian() -> impl Options {
    options().with_little_endian()
}

pub fn serialize_little<T>(value: &T) -> Result<Vec<u8>, bincode::Error>
where
    T: ?Sized + serde::Serialize,
{
    little_endian().serialize(value)
}

pub fn deserialize_little<'a, T>(bytes: &'a [u8]) -> Result<T, bincode::Error>
where
    T: serde::Deserialize<'a>,
{
    little_endian().deserialize(bytes)
}


#[derive(Serialize, Deserialize)]
struct HeightKey{
    code: u8,
    height: u64,
}

pub struct HeightRow {
    key: BlockKey,
    value: FullHash, // height ->  blockhash
}


#[derive(Serialize, Deserialize)]
struct BlockKey {
    code: u8,
    hash: FullHash,
}

pub struct BlockRow {
    key: BlockKey,
    value: Bytes, // serialized output
}

#[allow(dead_code)]
impl BlockRow {
    pub fn new_header(block_entry: &BlockHeader) -> BlockRow {
        BlockRow {
            key: BlockKey {
                code: b'B',
                hash: full_hash(&block_entry.block_hash()[..]),
            },
            value: serialize(&block_entry),
        }
    }

    pub fn first_sync_header_2(header_entry: &Vec<u8>) -> BlockRow {
        BlockRow {
            key: BlockKey {
                code: b'b',
                hash: full_hash(&header_entry),
            },
            value: serialize(&header_entry),
        }
    }

    pub fn first_sync_header(header_entry: &BlockHeader) -> BlockRow {
        BlockRow {
            key: BlockKey {
                code: b'b',
                hash: full_hash(&header_entry.block_hash()),
            },
            value: serialize(&header_entry),
        }
    }

    pub fn new_done(hash: FullHash) -> BlockRow {
        BlockRow {
            key: BlockKey { code: b'D', hash },
            value: vec![],
        }
    }

    fn header_sync_filter() -> Bytes {
        b"b".to_vec()
    }

    fn header_filter() -> Bytes {
        b"B".to_vec()
    }

    fn meta_key(hash: FullHash) -> Bytes {
        [b"M", &hash[..]].concat()
    }

    fn done_filter() -> Bytes {
        b"D".to_vec()
    }

    fn into_row(self) -> DBRow {
        DBRow {
            key: serialize_little(&self.key).unwrap(),
            value: self.value,
        }
    }

    fn from_row(row: DBRow) -> Self {
        BlockRow {
            key: deserialize_little(&row.key).unwrap(),
            value: row.value,
        }
    }
}

fn put<H: Sized + Encodable, I: Iterator<Item = H>>(
    db: DB,
    headers: I,
) -> Result<Height, Error> {
    let mut rows = vec![];

    for h in headers {
        let serilized_header = serialize(&h);
        
        rows.push(BlockRow::first_sync_header_2(&serilized_header).into_row());

    }
    db.write(rows.to_vec(), DBFlush::Enable);
    //db.iter_scan(prefix)

    Ok(1 as u64)
}

#[derive(Debug)]
pub struct RocksDB<H> {
    db: DB,
    genesis: H,
}

impl<H: 'static + Copy + Encodable + Decodable> Store for RocksDB<H> {
    type Header = H;
    
    fn genesis(&self) -> H {
        self.genesis
    }
    
    fn put<I: Iterator<Item = Self::Header>>(&mut self, headers: I) -> Result<Height, Error> {  

        Ok(5u64)
    }
    
    fn get(&self, height: Height) -> Result<Self::Header, Error> {
        todo!()
    }
    
    fn rollback(&mut self, height: Height) -> Result<(), Error> {
        todo!()
    }
    
    fn sync(&mut self) -> Result<(), Error> {
        todo!()
    }
    
    fn iter(&self) -> Box<dyn Iterator<Item = Result<(Height, Self::Header), Error>>> {
        todo!()
    }
    
    fn len(&self) -> Result<usize, Error> {
        todo!()
    }
    
    fn height(&self) -> Result<Height, Error> {
        todo!()
    }
    
    fn check(&self) -> Result<(), Error> {
        todo!()
    }
    
    fn heal(&self) -> Result<(), Error> {
        todo!()
    }

}