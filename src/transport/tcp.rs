//! TCP transport implementation
//!
//! Provides TCP-based transport for Oracle TNS protocol communication.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::{Config, DEFAULT_SDU};
use crate::constants::PACKET_HEADER_SIZE;
use crate::error::{Error, Result};
use crate::packet::{Packet, PacketHeader};

use super::Transport;

/// TCP transport for Oracle connections
pub struct TcpTransport {
    /// The underlying TCP stream
    stream: Option<TcpStream>,
    /// Read buffer for incoming data
    read_buf: BytesMut,
    /// Current SDU size
    sdu: u32,
    /// Whether to use large SDU (4-byte length field)
    large_sdu: bool,
    /// Connection timeout
    connect_timeout: Duration,
}

impl TcpTransport {
    /// Create a new TCP transport (not yet connected)
    pub fn new() -> Self {
        Self {
            stream: None,
            read_buf: BytesMut::with_capacity(DEFAULT_SDU as usize),
            sdu: DEFAULT_SDU,
            large_sdu: false,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Create a TCP transport with specified SDU size
    pub fn with_sdu(sdu: u32) -> Self {
        Self {
            stream: None,
            read_buf: BytesMut::with_capacity(sdu as usize),
            sdu,
            large_sdu: false,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Set the connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Connect to the specified address
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        let stream = timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::ConnectionTimeout(self.connect_timeout))?
            .map_err(Error::Io)?;

        // Set TCP options
        stream.set_nodelay(true).map_err(Error::Io)?;

        self.stream = Some(stream);
        Ok(())
    }

    /// Connect using a Config
    pub async fn connect_with_config(&mut self, config: &Config) -> Result<()> {
        self.sdu = config.sdu;
        self.connect_timeout = config.connect_timeout;
        self.read_buf = BytesMut::with_capacity(self.sdu as usize);

        self.connect(&config.socket_addr()).await
    }

    /// Get mutable access to the underlying stream
    fn stream_mut(&mut self) -> Result<&mut TcpStream> {
        self.stream
            .as_mut()
            .ok_or(Error::ConnectionClosed)
    }

    /// Read exactly n bytes from the stream
    async fn read_exact(&mut self, n: usize) -> Result<Bytes> {
        let stream = self.stream_mut()?;

        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::ConnectionClosed
            } else {
                Error::Io(e)
            }
        })?;

        Ok(Bytes::from(buf))
    }

    /// Read the packet header and determine packet length
    async fn read_packet_header(&mut self) -> Result<(PacketHeader, usize)> {
        let header_bytes = self.read_exact(PACKET_HEADER_SIZE).await?;

        let header = if self.large_sdu {
            PacketHeader::parse_large_sdu(&header_bytes)?
        } else {
            PacketHeader::parse(&header_bytes)?
        };

        let total_length = header.length as usize;

        Ok((header, total_length))
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.stream_mut()?;
        stream.write_all(data).await.map_err(Error::Io)?;
        stream.flush().await.map_err(Error::Io)?;
        Ok(())
    }

    async fn send_packet(&mut self, packet: Bytes) -> Result<()> {
        self.send(&packet).await
    }

    async fn receive_packet(&mut self) -> Result<Packet> {
        // Read packet header
        let (header, total_length) = self.read_packet_header().await?;

        // Calculate payload length
        let payload_length = total_length.saturating_sub(PACKET_HEADER_SIZE);

        // Read payload if any
        let payload = if payload_length > 0 {
            self.read_exact(payload_length).await?
        } else {
            Bytes::new()
        };

        Ok(Packet::new(header, payload))
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await.map_err(Error::Io)?;
        }
        Ok(())
    }

    fn sdu(&self) -> u32 {
        self.sdu
    }

    fn set_sdu(&mut self, sdu: u32) {
        self.sdu = sdu;
        // Resize buffer if needed
        if self.read_buf.capacity() < sdu as usize {
            self.read_buf = BytesMut::with_capacity(sdu as usize);
        }
    }

    fn uses_large_sdu(&self) -> bool {
        self.large_sdu
    }

    fn set_large_sdu(&mut self, large_sdu: bool) {
        self.large_sdu = large_sdu;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_new() {
        let transport = TcpTransport::new();
        assert!(!transport.is_connected());
        assert_eq!(transport.sdu(), DEFAULT_SDU);
        assert!(!transport.uses_large_sdu());
    }

    #[test]
    fn test_tcp_transport_with_sdu() {
        let transport = TcpTransport::with_sdu(16384);
        assert_eq!(transport.sdu(), 16384);
    }

    #[test]
    fn test_tcp_transport_set_sdu() {
        let mut transport = TcpTransport::new();
        transport.set_sdu(32768);
        assert_eq!(transport.sdu(), 32768);
    }

    #[test]
    fn test_tcp_transport_set_large_sdu() {
        let mut transport = TcpTransport::new();
        assert!(!transport.uses_large_sdu());
        transport.set_large_sdu(true);
        assert!(transport.uses_large_sdu());
    }
}
