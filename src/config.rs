//! Connection configuration and connection string parsing
//!
//! Supports Oracle EZConnect format:
//! - `host:port/service_name`
//! - `host/service_name`
//! - `host:port:sid`
//!
//! And TNS-style connect descriptors.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::constants::charset;
use crate::error::{Error, Result};
use crate::transport::TlsConfig;

/// Default Oracle port
pub const DEFAULT_PORT: u16 = 1521;

/// Default SDU size
pub const DEFAULT_SDU: u32 = 8192;

/// Default statement cache size (matches python-oracledb default)
pub const DEFAULT_STMTCACHESIZE: usize = 20;

/// Service identification method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceMethod {
    /// Connect using service name
    ServiceName(String),
    /// Connect using SID (legacy)
    Sid(String),
}

impl ServiceMethod {
    /// Get the service name if this is a ServiceName variant
    pub fn service_name(&self) -> Option<&str> {
        match self {
            ServiceMethod::ServiceName(s) => Some(s),
            ServiceMethod::Sid(_) => None,
        }
    }

    /// Get the SID if this is a Sid variant
    pub fn sid(&self) -> Option<&str> {
        match self {
            ServiceMethod::ServiceName(_) => None,
            ServiceMethod::Sid(s) => Some(s),
        }
    }
}

/// TLS mode for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// No TLS (plain TCP)
    #[default]
    Disable,
    /// Require TLS (TCPS)
    Require,
}

/// Connection configuration for Oracle databases.
///
/// This struct holds all the parameters needed to establish a connection to an
/// Oracle database, including host, port, credentials, TLS settings, and more.
///
/// # Examples
///
/// ## Basic connection
///
/// ```rust
/// use oracle_rs::Config;
///
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
/// ```
///
/// ## TLS connection with system certificates
///
/// ```rust
/// use oracle_rs::Config;
///
/// let config = Config::new("hostname", 2484, "service", "user", "password")
///     .with_tls()
///     .expect("TLS configuration failed");
/// ```
///
/// ## TLS connection with Oracle wallet
///
/// ```rust
/// use oracle_rs::Config;
///
/// let config = Config::new("hostname", 2484, "service", "user", "password")
///     .with_wallet("/path/to/wallet", Some("wallet_password"))
///     .expect("Wallet configuration failed");
/// ```
///
/// ## With custom options
///
/// ```rust
/// use oracle_rs::Config;
/// use std::time::Duration;
///
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
///     .connect_timeout(Duration::from_secs(30))
///     .stmtcachesize(50);
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Host to connect to
    pub host: String,
    /// Port to connect to
    pub port: u16,
    /// Service name or SID
    pub service: ServiceMethod,
    /// Username for authentication
    pub username: String,
    /// Password for authentication (stored temporarily)
    password: String,
    /// TLS mode
    pub tls_mode: TlsMode,
    /// TLS configuration (certificates, wallet, etc.)
    pub tls_config: Option<TlsConfig>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// SDU (Session Data Unit) size
    pub sdu: u32,
    /// Client charset ID
    pub charset_id: u16,
    /// National charset ID
    pub ncharset_id: u16,
    /// Statement cache size (0 = disabled)
    pub stmtcachesize: usize,
}

impl Config {
    /// Create a new configuration with service name
    pub fn new(
        host: impl Into<String>,
        port: u16,
        service_name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            service: ServiceMethod::ServiceName(service_name.into()),
            username: username.into(),
            password: password.into(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
        }
    }

    /// Create a new configuration with SID
    pub fn with_sid(
        host: impl Into<String>,
        port: u16,
        sid: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            service: ServiceMethod::Sid(sid.into()),
            username: username.into(),
            password: password.into(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
        }
    }

    /// Set TLS mode
    pub fn tls(mut self, mode: TlsMode) -> Self {
        self.tls_mode = mode;
        self
    }

    /// Set TLS configuration
    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self.tls_mode = TlsMode::Require;
        self
    }

    /// Check if TLS is enabled
    pub fn is_tls_enabled(&self) -> bool {
        self.tls_mode == TlsMode::Require
    }

    /// Enable TLS with system root certificates.
    ///
    /// This configures the connection to use TLS (TCPS protocol) with the
    /// system's trusted root certificate store for server verification.
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 2484, "service", "user", "password")
    ///     .with_tls()
    ///     .expect("TLS configuration failed");
    /// ```
    pub fn with_tls(mut self) -> Result<Self> {
        let tls_config = TlsConfig::new();
        // Validate that TLS config can be built
        tls_config.build_client_config()?;
        self.tls_config = Some(tls_config);
        self.tls_mode = TlsMode::Require;
        Ok(self)
    }

    /// Enable TLS with an Oracle wallet.
    ///
    /// Oracle wallets (ewallet.p12 or ewallet.pem files) contain certificates
    /// and keys for secure connections. This is the standard way to configure
    /// TLS for Oracle Cloud and enterprise deployments.
    ///
    /// # Arguments
    ///
    /// * `wallet_path` - Path to the wallet directory containing ewallet.pem
    /// * `wallet_password` - Optional password for encrypted wallets
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 2484, "service", "user", "password")
    ///     .with_wallet("/path/to/wallet", Some("wallet_password"))
    ///     .expect("Wallet configuration failed");
    /// ```
    pub fn with_wallet(
        mut self,
        wallet_path: impl Into<String>,
        wallet_password: Option<&str>,
    ) -> Result<Self> {
        let tls_config = TlsConfig::new()
            .with_wallet(wallet_path, wallet_password.map(|s| s.to_string()));
        // Validate that TLS config can be built
        tls_config.build_client_config()?;
        self.tls_config = Some(tls_config);
        self.tls_mode = TlsMode::Require;
        Ok(self)
    }

    /// Configure DRCP (Database Resident Connection Pooling).
    ///
    /// DRCP allows the database server to maintain a pool of connections that
    /// can be shared across multiple client processes, reducing server resource
    /// usage.
    ///
    /// # Arguments
    ///
    /// * `connection_class` - Name identifying this class of connections
    /// * `purity` - Either "self" (dedicated) or "new" (can share with others)
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("hostname", 1521, "service", "user", "password")
    ///     .with_drcp("my_app", "self");
    /// ```
    pub fn with_drcp(self, _connection_class: &str, _purity: &str) -> Self {
        // TODO: Implement DRCP configuration storage
        // For now, DRCP is handled at connection time via the connect descriptor
        self
    }

    /// Set the statement cache size.
    ///
    /// Statement caching improves performance by reusing parsed SQL statements.
    /// Set to 0 to disable caching.
    ///
    /// Default is 20 (matches python-oracledb default).
    ///
    /// # Example
    ///
    /// ```rust
    /// use oracle_rs::Config;
    ///
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
    ///     .with_statement_cache_size(100);
    /// ```
    pub fn with_statement_cache_size(mut self, size: usize) -> Self {
        self.stmtcachesize = size;
        self
    }

    /// Set connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set SDU size
    pub fn sdu(mut self, sdu: u32) -> Self {
        self.sdu = sdu;
        self
    }

    /// Set statement cache size
    ///
    /// Set to 0 to disable statement caching.
    /// Default is 20 (matches python-oracledb default).
    pub fn stmtcachesize(mut self, size: usize) -> Self {
        self.stmtcachesize = size;
        self
    }

    /// Get the password (for authentication)
    pub(crate) fn password(&self) -> &str {
        &self.password
    }

    /// Set the password
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = password.into();
    }

    /// Set the username
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into();
    }

    /// Build a TNS connect descriptor string
    pub fn build_connect_string(&self) -> String {
        let mut parts = Vec::new();

        // Address
        let protocol = match self.tls_mode {
            TlsMode::Disable => "TCP",
            TlsMode::Require => "TCPS",
        };
        parts.push(format!(
            "(ADDRESS=(PROTOCOL={})(HOST={})(PORT={}))",
            protocol, self.host, self.port
        ));

        // Connect data
        let service_part = match &self.service {
            ServiceMethod::ServiceName(name) => format!("(SERVICE_NAME={})", name),
            ServiceMethod::Sid(sid) => format!("(SID={})", sid),
        };
        parts.push(format!("(CONNECT_DATA={})", service_part));

        format!("(DESCRIPTION={})", parts.join(""))
    }

    /// Get the socket address string
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: DEFAULT_PORT,
            service: ServiceMethod::ServiceName("FREEPDB1".to_string()),
            username: String::new(),
            password: String::new(),
            tls_mode: TlsMode::Disable,
            tls_config: None,
            connect_timeout: Duration::from_secs(10),
            sdu: DEFAULT_SDU,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            stmtcachesize: DEFAULT_STMTCACHESIZE,
        }
    }
}

/// Parse an EZConnect-style connection string
///
/// Formats supported:
/// - `host:port/service_name`
/// - `host/service_name`
/// - `host:port:sid`
/// - `//host:port/service_name` (with optional leading slashes)
impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();

        // Strip leading slashes if present
        let s = s.trim_start_matches('/');

        if s.is_empty() {
            return Err(Error::InvalidConnectionString(
                "empty connection string".to_string(),
            ));
        }

        // Check for TNS descriptor format
        if s.starts_with('(') {
            return Err(Error::InvalidConnectionString(
                "TNS descriptor format not yet supported, use EZConnect format".to_string(),
            ));
        }

        // Parse EZConnect format
        // Format: [//]host[:port][/service_name] or host:port:sid

        let mut config = Config::default();

        // Check for service_name format (contains /)
        if let Some(slash_pos) = s.find('/') {
            let host_port = &s[..slash_pos];
            let service_name = &s[slash_pos + 1..];

            if service_name.is_empty() {
                return Err(Error::InvalidConnectionString(
                    "missing service name after /".to_string(),
                ));
            }

            config.service = ServiceMethod::ServiceName(service_name.to_string());

            // Parse host:port
            if let Some(colon_pos) = host_port.find(':') {
                config.host = host_port[..colon_pos].to_string();
                config.port = host_port[colon_pos + 1..]
                    .parse()
                    .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
            } else {
                config.host = host_port.to_string();
                config.port = DEFAULT_PORT;
            }
        } else {
            // Check for SID format (host:port:sid)
            let parts: Vec<&str> = s.split(':').collect();

            match parts.len() {
                1 => {
                    // Just host, use defaults
                    config.host = parts[0].to_string();
                }
                2 => {
                    // host:port
                    config.host = parts[0].to_string();
                    config.port = parts[1]
                        .parse()
                        .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
                }
                3 => {
                    // host:port:sid
                    config.host = parts[0].to_string();
                    config.port = parts[1]
                        .parse()
                        .map_err(|_| Error::InvalidConnectionString("invalid port number".to_string()))?;
                    config.service = ServiceMethod::Sid(parts[2].to_string());
                }
                _ => {
                    return Err(Error::InvalidConnectionString(
                        "too many colons in connection string".to_string(),
                    ));
                }
            }
        }

        if config.host.is_empty() {
            return Err(Error::InvalidConnectionString(
                "missing host".to_string(),
            ));
        }

        Ok(config)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.service {
            ServiceMethod::ServiceName(name) => {
                write!(f, "{}:{}/{}", self.host, self.port, name)
            }
            ServiceMethod::Sid(sid) => {
                write!(f, "{}:{}:{}", self.host, self.port, sid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ezconnect_full() {
        let config: Config = "myhost:1522/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
        assert_eq!(
            config.service,
            ServiceMethod::ServiceName("myservice".to_string())
        );
    }

    #[test]
    fn test_parse_ezconnect_default_port() {
        let config: Config = "myhost/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(
            config.service,
            ServiceMethod::ServiceName("myservice".to_string())
        );
    }

    #[test]
    fn test_parse_ezconnect_with_slashes() {
        let config: Config = "//myhost:1522/myservice".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
    }

    #[test]
    fn test_parse_ezconnect_sid_format() {
        let config: Config = "myhost:1522:ORCL".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
        assert_eq!(config.service, ServiceMethod::Sid("ORCL".to_string()));
    }

    #[test]
    fn test_parse_host_only() {
        let config: Config = "myhost".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_parse_host_port() {
        let config: Config = "myhost:1522".parse().unwrap();
        assert_eq!(config.host, "myhost");
        assert_eq!(config.port, 1522);
    }

    #[test]
    fn test_parse_empty() {
        let result: Result<Config> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_port() {
        let result: Result<Config> = "myhost:notaport/service".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_connect_string() {
        let config = Config::new("myhost", 1522, "myservice", "user", "pass");
        let connect_str = config.build_connect_string();
        assert!(connect_str.contains("(HOST=myhost)"));
        assert!(connect_str.contains("(PORT=1522)"));
        assert!(connect_str.contains("(SERVICE_NAME=myservice)"));
        assert!(connect_str.contains("(PROTOCOL=TCP)"));
    }

    #[test]
    fn test_build_connect_string_sid() {
        let config = Config::with_sid("myhost", 1522, "ORCL", "user", "pass");
        let connect_str = config.build_connect_string();
        assert!(connect_str.contains("(SID=ORCL)"));
    }

    #[test]
    fn test_config_display() {
        let config = Config::new("myhost", 1522, "myservice", "user", "pass");
        assert_eq!(config.to_string(), "myhost:1522/myservice");

        let config_sid = Config::with_sid("myhost", 1522, "ORCL", "user", "pass");
        assert_eq!(config_sid.to_string(), "myhost:1522:ORCL");
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = Config::new("host", 1521, "svc", "user", "pass")
            .tls(TlsMode::Require)
            .connect_timeout(Duration::from_secs(30))
            .sdu(16384);

        assert_eq!(config.tls_mode, TlsMode::Require);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.sdu, 16384);
    }
}
