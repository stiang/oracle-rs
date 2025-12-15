//! Connection capabilities negotiation
//!
//! This module handles the compile-time (CCAP) and runtime (RCAP) capabilities
//! that are negotiated between client and server during connection establishment.

use crate::constants::{
    accept_flags, ccap_index, ccap_value, charset, rcap_index, rcap_value, service_options,
    version,
};

/// Driver name sent during protocol negotiation
pub const DRIVER_NAME: &str = "oracle-rs : 0.1.0";

/// Capabilities negotiated between client and server
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Protocol options from server
    pub protocol_options: u16,
    /// Character set ID for database communication
    pub charset_id: u16,
    /// National character set ID
    pub ncharset_id: u16,
    /// Compile-time capabilities array (CCAP)
    pub compile_caps: Vec<u8>,
    /// Runtime capabilities array (RCAP)
    pub runtime_caps: Vec<u8>,
    /// TTC field version
    pub ttc_field_version: u8,
    /// Negotiated SDU size
    pub sdu: u32,
    /// Maximum string size (4000 or 32767)
    pub max_string_size: u32,
    /// Whether fast authentication is supported
    pub supports_fast_auth: bool,
    /// Whether OOB (out of band) is supported
    pub supports_oob: bool,
    /// Whether end-of-response markers are supported
    pub supports_end_of_response: bool,
    /// Whether pipelining is supported
    pub supports_pipelining: bool,
    /// Whether request boundaries are supported
    pub supports_request_boundaries: bool,
    /// Combo key derived during authentication (for encryption)
    pub combo_key: Option<Vec<u8>>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::new()
    }
}

impl Capabilities {
    /// Create new capabilities with default client values
    pub fn new() -> Self {
        let mut caps = Self {
            protocol_version: 0,
            protocol_options: 0,
            charset_id: charset::UTF8,
            ncharset_id: charset::UTF16,
            compile_caps: vec![0; ccap_index::MAX],
            runtime_caps: vec![0; rcap_index::MAX],
            ttc_field_version: ccap_value::FIELD_VERSION_MAX,
            sdu: 8192,
            max_string_size: 4000,
            supports_fast_auth: false,
            supports_oob: false,
            supports_end_of_response: false,
            supports_pipelining: false,
            supports_request_boundaries: false,
            combo_key: None,
        };

        caps.init_compile_caps();
        caps.init_runtime_caps();
        caps
    }

    /// Initialize compile-time capabilities
    fn init_compile_caps(&mut self) {
        use ccap_index::*;
        use ccap_value::*;

        self.compile_caps[SQL_VERSION] = SQL_VERSION_MAX;

        self.compile_caps[LOGON_TYPES] =
            O5LOGON | O5LOGON_NP | O7LOGON | O8LOGON_LONG_IDENTIFIER | O9LOGON_LONG_PASSWORD;

        self.compile_caps[FEATURE_BACKPORT] = CTB_IMPLICIT_POOL | CTB_OAUTH_MSG_ON_ERR;

        self.compile_caps[FIELD_VERSION] = self.ttc_field_version;

        self.compile_caps[SERVER_DEFINE_CONV] = 1;
        self.compile_caps[DEQUEUE_WITH_SELECTOR] = 1;

        self.compile_caps[TTC1] = FAST_BVEC | END_OF_CALL_STATUS | IND_RCD;

        self.compile_caps[OCI1] = FAST_SESSION_PROPAGATE | APP_CTX_PIGGYBACK;

        self.compile_caps[TDS_VERSION] = TDS_VERSION_MAX;
        self.compile_caps[RPC_VERSION] = RPC_VERSION_MAX;
        self.compile_caps[RPC_SIG] = RPC_SIG_VALUE;
        self.compile_caps[DBF_VERSION] = DBF_VERSION_MAX;

        self.compile_caps[LOB] = LOB_UB8_SIZE
            | LOB_ENCS
            | LOB_PREFETCH_LENGTH
            | LOB_TEMP_SIZE
            | LOB_12C
            | LOB_PREFETCH_DATA;

        self.compile_caps[UB2_DTY] = 1;

        self.compile_caps[LOB2] = LOB2_QUASI | LOB2_2GB_PREFETCH;

        self.compile_caps[TTC3] = IMPLICIT_RESULTS | BIG_CHUNK_CLR | KEEP_OUT_ORDER | LTXID;

        self.compile_caps[TTC2] = ZLNP;

        self.compile_caps[OCI2] = DRCP;

        self.compile_caps[OCI3] = OCI3_OCSSYNC;

        self.compile_caps[CLIENT_FN] = CLIENT_FN_MAX;

        self.compile_caps[SESS_SIGNATURE_VERSION] = FIELD_VERSION_12_2;

        self.compile_caps[TTC4] = INBAND_NOTIFICATION | EXPLICIT_BOUNDARY;

        self.compile_caps[TTC5] = VECTOR_SUPPORT
            | TOKEN_SUPPORTED
            | PIPELINING_SUPPORT
            | PIPELINING_BREAK
            | SESSIONLESS_TXNS;

        self.compile_caps[VECTOR_FEATURES] = VECTOR_FEATURE_BINARY | VECTOR_FEATURE_SPARSE;
    }

    /// Initialize runtime capabilities
    fn init_runtime_caps(&mut self) {
        use rcap_index::*;
        use rcap_value::*;

        self.runtime_caps[COMPAT] = COMPAT_81;
        self.runtime_caps[TTC] = TTC_ZERO_COPY | TTC_32K;
    }

    /// Adjust capabilities based on ACCEPT packet response
    pub fn adjust_for_protocol(
        &mut self,
        protocol_version: u16,
        protocol_options: u16,
        flags2: u32,
    ) {
        self.protocol_version = protocol_version;
        self.protocol_options = protocol_options;

        // Check OOB support
        self.supports_oob = (protocol_options & service_options::CAN_RECV_ATTENTION) != 0;

        // Check fast auth support
        if (flags2 & accept_flags::FAST_AUTH) != 0 {
            self.supports_fast_auth = true;
        }

        // Check end of response support
        if protocol_version >= version::MIN_END_OF_RESPONSE
            && (flags2 & accept_flags::HAS_END_OF_RESPONSE) != 0
        {
            self.compile_caps[ccap_index::TTC4] |= ccap_value::END_OF_REQUEST;
            self.supports_end_of_response = true;
            self.supports_pipelining = true;
        }
    }

    /// Adjust capabilities based on server's compile-time capabilities
    pub fn adjust_for_server_compile_caps(&mut self, server_caps: &[u8]) {
        // Adjust field version to minimum of client and server
        if server_caps.len() > ccap_index::FIELD_VERSION {
            let server_version = server_caps[ccap_index::FIELD_VERSION];
            if server_version < self.ttc_field_version {
                self.ttc_field_version = server_version;
                self.compile_caps[ccap_index::FIELD_VERSION] = server_version;
            }
        }

        // Check for explicit boundary support
        if server_caps.len() > ccap_index::TTC4 {
            if (server_caps[ccap_index::TTC4] & ccap_value::EXPLICIT_BOUNDARY) != 0 {
                self.supports_request_boundaries = true;
            }
        }

        // Disable end of response if field version is too old
        if self.ttc_field_version < ccap_value::FIELD_VERSION_23_4 && self.supports_end_of_response
        {
            self.compile_caps[ccap_index::TTC4] &= !ccap_value::END_OF_REQUEST;
            self.supports_end_of_response = false;
        }
    }

    /// Adjust capabilities based on server's runtime capabilities
    pub fn adjust_for_server_runtime_caps(&mut self, server_caps: &[u8]) {
        // Check max string size
        if server_caps.len() > rcap_index::TTC {
            if (server_caps[rcap_index::TTC] & rcap_value::TTC_32K) != 0 {
                self.max_string_size = 32767;
            } else {
                self.max_string_size = 4000;
            }

            // Check session state ops support
            if (server_caps[rcap_index::TTC] & rcap_value::TTC_SESSION_STATE_OPS) == 0 {
                self.supports_request_boundaries = false;
            }
        }
    }

    /// Check if the national character set is supported
    pub fn check_ncharset_id(&self) -> crate::error::Result<()> {
        if self.ncharset_id != charset::UTF16 && self.ncharset_id != charset::AL16UTF8 {
            return Err(crate::error::Error::FeatureNotSupported(format!(
                "national character set {} is not supported (only UTF16 and AL16UTF8)",
                self.ncharset_id
            )));
        }
        Ok(())
    }

    /// Check if we support boolean type (Oracle 23.1+)
    pub fn supports_bool(&self) -> bool {
        self.ttc_field_version >= ccap_value::FIELD_VERSION_23_1
    }

    /// Check if we support large OSON field names (Oracle 23.1+)
    pub fn supports_large_oson_fname(&self) -> bool {
        self.ttc_field_version >= ccap_value::FIELD_VERSION_23_1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_default() {
        let caps = Capabilities::new();

        assert_eq!(caps.charset_id, charset::UTF8);
        assert_eq!(caps.ncharset_id, charset::UTF16);
        assert_eq!(caps.compile_caps.len(), ccap_index::MAX);
        assert_eq!(caps.runtime_caps.len(), rcap_index::MAX);
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_MAX);
        assert!(!caps.supports_fast_auth);
        assert!(!caps.supports_oob);
    }

    #[test]
    fn test_compile_caps_initialization() {
        let caps = Capabilities::new();

        assert_eq!(
            caps.compile_caps[ccap_index::SQL_VERSION],
            ccap_value::SQL_VERSION_MAX
        );
        assert_eq!(
            caps.compile_caps[ccap_index::FIELD_VERSION],
            ccap_value::FIELD_VERSION_MAX
        );
        assert_ne!(caps.compile_caps[ccap_index::LOGON_TYPES], 0);
        assert_ne!(caps.compile_caps[ccap_index::TTC1], 0);
    }

    #[test]
    fn test_runtime_caps_initialization() {
        let caps = Capabilities::new();

        assert_eq!(caps.runtime_caps[rcap_index::COMPAT], rcap_value::COMPAT_81);
        assert_ne!(caps.runtime_caps[rcap_index::TTC], 0);
    }

    #[test]
    fn test_adjust_for_protocol() {
        let mut caps = Capabilities::new();

        // Simulate ACCEPT response with fast auth and end of response
        caps.adjust_for_protocol(
            319,
            service_options::CAN_RECV_ATTENTION,
            accept_flags::FAST_AUTH | accept_flags::HAS_END_OF_RESPONSE,
        );

        assert_eq!(caps.protocol_version, 319);
        assert!(caps.supports_fast_auth);
        assert!(caps.supports_oob);
        assert!(caps.supports_end_of_response);
        assert!(caps.supports_pipelining);
    }

    #[test]
    fn test_adjust_for_protocol_no_features() {
        let mut caps = Capabilities::new();

        caps.adjust_for_protocol(315, 0, 0);

        assert_eq!(caps.protocol_version, 315);
        assert!(!caps.supports_fast_auth);
        assert!(!caps.supports_oob);
        assert!(!caps.supports_end_of_response);
    }

    #[test]
    fn test_adjust_for_server_compile_caps() {
        let mut caps = Capabilities::new();

        // Server has lower field version
        let mut server_caps = vec![0; ccap_index::MAX];
        server_caps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_12_2;

        caps.adjust_for_server_compile_caps(&server_caps);

        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_12_2);
        assert_eq!(
            caps.compile_caps[ccap_index::FIELD_VERSION],
            ccap_value::FIELD_VERSION_12_2
        );
    }

    #[test]
    fn test_adjust_for_server_runtime_caps() {
        let mut caps = Capabilities::new();

        // Server supports 32K strings
        let mut server_caps = vec![0; rcap_index::MAX];
        server_caps[rcap_index::TTC] = rcap_value::TTC_32K;

        caps.adjust_for_server_runtime_caps(&server_caps);

        assert_eq!(caps.max_string_size, 32767);
    }

    #[test]
    fn test_adjust_for_server_runtime_caps_no_32k() {
        let mut caps = Capabilities::new();

        // Server doesn't support 32K strings
        let server_caps = vec![0; rcap_index::MAX];

        caps.adjust_for_server_runtime_caps(&server_caps);

        assert_eq!(caps.max_string_size, 4000);
    }

    #[test]
    fn test_check_ncharset_id_valid() {
        let mut caps = Capabilities::new();

        caps.ncharset_id = charset::UTF16;
        assert!(caps.check_ncharset_id().is_ok());

        caps.ncharset_id = charset::AL16UTF8;
        assert!(caps.check_ncharset_id().is_ok());
    }

    #[test]
    fn test_check_ncharset_id_invalid() {
        let mut caps = Capabilities::new();

        caps.ncharset_id = 999;
        assert!(caps.check_ncharset_id().is_err());
    }

    #[test]
    fn test_supports_bool() {
        let mut caps = Capabilities::new();

        caps.ttc_field_version = ccap_value::FIELD_VERSION_23_1;
        assert!(caps.supports_bool());

        caps.ttc_field_version = ccap_value::FIELD_VERSION_12_2;
        assert!(!caps.supports_bool());
    }
}
