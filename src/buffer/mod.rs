//! Buffer abstractions for TNS protocol encoding/decoding
//!
//! This module provides efficient buffer types for reading and writing
//! binary TNS protocol data.

mod read;
mod write;

pub use read::ReadBuffer;
pub use write::WriteBuffer;
