//! Transport layer for Oracle connections
//!
//! Handles the low-level TCP communication with the Oracle database server.

mod tcp;
pub mod tls;

pub use tcp::TcpTransport;
pub use tls::{Protocol, TlsConfig, TlsOracleStream, connect_tls};

use bytes::Bytes;

use crate::error::Result;
use crate::packet::Packet;

/// Trait for transport implementations
#[async_trait::async_trait]
pub trait Transport: Send {
    /// Send raw bytes to the server
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Send a packet to the server
    async fn send_packet(&mut self, packet: Bytes) -> Result<()>;

    /// Receive a packet from the server
    async fn receive_packet(&mut self) -> Result<Packet>;

    /// Check if the transport is connected
    fn is_connected(&self) -> bool;

    /// Close the connection
    async fn close(&mut self) -> Result<()>;

    /// Get the current SDU size
    fn sdu(&self) -> u32;

    /// Set the SDU size (after negotiation)
    fn set_sdu(&mut self, sdu: u32);

    /// Check if using large SDU (4-byte length field)
    fn uses_large_sdu(&self) -> bool;

    /// Set whether to use large SDU
    fn set_large_sdu(&mut self, large_sdu: bool);
}
