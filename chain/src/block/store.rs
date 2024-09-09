//! Block storage backends.

pub use nakamoto_common::block::store::*;

pub mod io;
pub mod memory;
//pub mod db;
pub mod io_seal;

pub use io::File;
pub use memory::Memory;
//pub use db::DB;
pub use io_seal::File as SealFile;

// /// 
// pub enum StoreAll<H> {
//     ///
//     Seal(Result<SealFile<H>, Error>),
//     ///
//     Normal(Result<File<H>, Error>),
// }

// impl <H> StoreAll<H> {
//     fn get_value(&self) -> i32 {
//         match self {
//             StoreAll::Seal(a) => a,
//             StoreAll::Normal(b) => b,
//         }
//     }
// }