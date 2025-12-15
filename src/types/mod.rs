//! Oracle data type encoding and decoding
//!
//! This module provides functions for encoding Rust types to Oracle's wire format
//! and decoding Oracle wire format to Rust types.

mod number;
mod date;
mod binary;
mod rowid;
mod lob;
mod oson;
mod vector;
mod cursor;
mod pickle;

pub use number::{decode_oracle_number, encode_oracle_number, OracleNumber};
pub use date::{
    decode_oracle_date, decode_oracle_timestamp, encode_oracle_date, encode_oracle_timestamp,
    OracleDate, OracleTimestamp,
};
pub use binary::{
    decode_binary_double, decode_binary_float, encode_binary_double, encode_binary_float,
};
pub use rowid::{decode_rowid, parse_rowid_string, RowId, MAX_ROWID_LENGTH};
pub use lob::{LobData, LobLocator, LobValue};
pub use oson::{OsonDecoder, OsonEncoder};
pub use vector::{
    decode_vector, encode_vector, OracleVector, SparseVector, VectorData, VectorFormat,
    VECTOR_MAX_LENGTH,
};
pub use cursor::RefCursor;
pub use pickle::{decode_collection, encode_collection};
