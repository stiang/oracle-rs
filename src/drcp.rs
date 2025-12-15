//! Database Resident Connection Pooling (DRCP) support
//!
//! DRCP is Oracle's server-side connection pooling feature that allows multiple
//! client connections to share a smaller pool of server processes, reducing
//! resource usage on the database server.
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, Config, DrcpOptions};
//!
//! // Configure DRCP
//! let drcp = DrcpOptions::new()
//!     .with_connection_class("MyApp")
//!     .with_purity(SessionPurity::New);
//!
//! // Connect with DRCP enabled
//! let config = Config::new("host", 1521, "service", "user", "pass")
//!     .with_drcp(drcp);
//!
//! let conn = Connection::connect_with_config(config).await?;
//!
//! // Connection will automatically release to pool on close
//! conn.close().await?;
//! ```

/// Session purity for DRCP connections
///
/// Controls whether to get a fresh session or allow reusing an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPurity {
    /// Allow reusing an existing session (default)
    #[default]
    Default,
    /// Request a brand new session
    New,
    /// Request an existing session (fail if none available)
    Self_,
}

/// Session release mode for DRCP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ReleaseMode {
    /// Normal release back to pool
    #[default]
    Normal = 0,
    /// Release with deauthentication
    Deauthenticate = 0x00000002,
}

/// DRCP configuration options
#[derive(Debug, Clone, Default)]
pub struct DrcpOptions {
    /// Connection class for session affinity
    pub connection_class: Option<String>,
    /// Session purity requirement
    pub purity: SessionPurity,
    /// Whether DRCP is enabled
    pub enabled: bool,
}

impl DrcpOptions {
    /// Create new DRCP options
    pub fn new() -> Self {
        Self {
            connection_class: None,
            purity: SessionPurity::Default,
            enabled: true,
        }
    }

    /// Set the connection class for session affinity
    ///
    /// Sessions with the same connection class may be reused, allowing
    /// for caching of session state (PL/SQL package variables, etc.)
    pub fn with_connection_class(mut self, class: impl Into<String>) -> Self {
        self.connection_class = Some(class.into());
        self
    }

    /// Set the session purity
    pub fn with_purity(mut self, purity: SessionPurity) -> Self {
        self.purity = purity;
        self
    }

    /// Disable DRCP
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check if DRCP is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// DRCP session state
#[derive(Debug, Clone, Default)]
pub struct DrcpSession {
    /// Whether a DRCP session is held
    pub is_held: bool,
    /// Session tag (for session affinity)
    pub tag: Option<String>,
    /// Whether the session state has changed
    pub state_changed: bool,
}

impl DrcpSession {
    /// Create a new DRCP session state
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark that a DRCP session is held
    pub fn set_held(&mut self, held: bool) {
        self.is_held = held;
    }

    /// Set the session tag
    pub fn set_tag(&mut self, tag: Option<String>) {
        self.tag = tag;
    }

    /// Check if session state has changed
    pub fn is_state_changed(&self) -> bool {
        self.state_changed
    }

    /// Mark session state as changed
    pub fn mark_state_changed(&mut self) {
        self.state_changed = true;
    }

    /// Clear the state changed flag
    pub fn clear_state_changed(&mut self) {
        self.state_changed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drcp_options_default() {
        let opts = DrcpOptions::new();
        assert!(opts.enabled);
        assert!(opts.connection_class.is_none());
        assert_eq!(opts.purity, SessionPurity::Default);
    }

    #[test]
    fn test_drcp_options_builder() {
        let opts = DrcpOptions::new()
            .with_connection_class("MyApp")
            .with_purity(SessionPurity::New);

        assert!(opts.is_enabled());
        assert_eq!(opts.connection_class, Some("MyApp".to_string()));
        assert_eq!(opts.purity, SessionPurity::New);
    }

    #[test]
    fn test_drcp_options_disabled() {
        let opts = DrcpOptions::new().disabled();
        assert!(!opts.is_enabled());
    }

    #[test]
    fn test_drcp_session_state() {
        let mut session = DrcpSession::new();
        assert!(!session.is_held);

        session.set_held(true);
        assert!(session.is_held);

        session.set_tag(Some("tag1".to_string()));
        assert_eq!(session.tag, Some("tag1".to_string()));
    }

    #[test]
    fn test_drcp_session_state_changed() {
        let mut session = DrcpSession::new();
        assert!(!session.is_state_changed());

        session.mark_state_changed();
        assert!(session.is_state_changed());

        session.clear_state_changed();
        assert!(!session.is_state_changed());
    }

    #[test]
    fn test_session_purity_values() {
        assert_eq!(SessionPurity::Default, SessionPurity::default());
    }

    #[test]
    fn test_release_mode_values() {
        assert_eq!(ReleaseMode::Normal as u32, 0);
        assert_eq!(ReleaseMode::Deauthenticate as u32, 0x00000002);
    }
}
