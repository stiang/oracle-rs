//! TNS protocol constants
//!
//! This module contains all the constants used in the Oracle TNS protocol,
//! derived from the official python-oracledb thin driver and oracle-nio.

// =============================================================================
// Packet Types
// =============================================================================

/// TNS packet types (found in packet header byte 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Initial connection request from client
    Connect = 1,
    /// Server accepts connection
    Accept = 2,
    /// Server acknowledges (rarely used)
    Ack = 3,
    /// Server refuses connection
    Refuse = 4,
    /// Server redirects to different address
    Redirect = 5,
    /// Data packet (contains protocol messages)
    Data = 6,
    /// Null packet
    Null = 7,
    /// Abort connection
    Abort = 9,
    /// Request packet resend
    Resend = 11,
    /// Marker packet (break/reset/interrupt)
    Marker = 12,
    /// Attention packet
    Attention = 13,
    /// Control packet (inband notifications)
    Control = 14,
}

impl TryFrom<u8> for PacketType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::Connect),
            2 => Ok(PacketType::Accept),
            3 => Ok(PacketType::Ack),
            4 => Ok(PacketType::Refuse),
            5 => Ok(PacketType::Redirect),
            6 => Ok(PacketType::Data),
            7 => Ok(PacketType::Null),
            9 => Ok(PacketType::Abort),
            11 => Ok(PacketType::Resend),
            12 => Ok(PacketType::Marker),
            13 => Ok(PacketType::Attention),
            14 => Ok(PacketType::Control),
            _ => Err(crate::error::Error::InvalidPacketType(value)),
        }
    }
}

// =============================================================================
// Packet Flags
// =============================================================================

/// Packet flags (found in packet header byte 6)
#[allow(missing_docs)]
pub mod packet_flags {
    pub const REDIRECT: u8 = 0x04;
    pub const TLS_RENEG: u8 = 0x08;
}

// =============================================================================
// Data Flags (for DATA packets)
// =============================================================================

/// Data flags (first 2 bytes of DATA packet payload)
#[allow(missing_docs)]
pub mod data_flags {
    pub const BEGIN_PIPELINE: u16 = 0x1000;
    pub const END_OF_REQUEST: u16 = 0x0800;
    pub const END_OF_RESPONSE: u16 = 0x2000;
    pub const EOF: u16 = 0x0040;
}

// =============================================================================
// Marker Types
// =============================================================================

/// Marker types for MARKER packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MarkerType {
    /// Break marker - interrupts current operation
    Break = 1,
    /// Reset marker - resets connection state
    Reset = 2,
    /// Interrupt marker - signals interrupt request
    Interrupt = 3,
}

// =============================================================================
// Message Types (within DATA packets)
// =============================================================================

/// Message types found in DATA packet payloads
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Protocol negotiation
    Protocol = 1,
    /// Data type negotiation
    DataTypes = 2,
    /// Execute function (TTC function call)
    Function = 3,
    /// Error response
    Error = 4,
    /// Row header
    RowHeader = 6,
    /// Row data
    RowData = 7,
    /// OPI parameter response
    Parameter = 8,
    /// Call status
    Status = 9,
    /// I/O vector
    IoVector = 11,
    /// LOB data
    LobData = 14,
    /// Warning message
    Warning = 15,
    /// Column describe information
    DescribeInfo = 16,
    /// Piggyback function
    Piggyback = 17,
    /// Flush out binds
    FlushOutBinds = 19,
    /// Bit vector
    BitVector = 21,
    /// Server-side piggyback
    ServerSidePiggyback = 23,
    /// One-way function
    OnewayFn = 26,
    /// Implicit resultset
    ImplicitResultset = 27,
    /// Renegotiate
    Renegotiate = 28,
    /// End of response marker
    EndOfResponse = 29,
    /// Token message
    Token = 33,
    /// Fast authentication
    FastAuth = 34,
}

impl TryFrom<u8> for MessageType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(MessageType::Protocol),
            2 => Ok(MessageType::DataTypes),
            3 => Ok(MessageType::Function),
            4 => Ok(MessageType::Error),
            6 => Ok(MessageType::RowHeader),
            7 => Ok(MessageType::RowData),
            8 => Ok(MessageType::Parameter),
            9 => Ok(MessageType::Status),
            11 => Ok(MessageType::IoVector),
            14 => Ok(MessageType::LobData),
            15 => Ok(MessageType::Warning),
            16 => Ok(MessageType::DescribeInfo),
            17 => Ok(MessageType::Piggyback),
            19 => Ok(MessageType::FlushOutBinds),
            21 => Ok(MessageType::BitVector),
            23 => Ok(MessageType::ServerSidePiggyback),
            26 => Ok(MessageType::OnewayFn),
            27 => Ok(MessageType::ImplicitResultset),
            28 => Ok(MessageType::Renegotiate),
            29 => Ok(MessageType::EndOfResponse),
            33 => Ok(MessageType::Token),
            34 => Ok(MessageType::FastAuth),
            _ => Err(crate::error::Error::InvalidMessageType(value)),
        }
    }
}

// =============================================================================
// TTC Function Codes
// =============================================================================

/// TTC (Two-Task Common) function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionCode {
    /// Reexecute previous statement
    Reexecute = 4,
    /// Fetch rows
    Fetch = 5,
    /// Logoff from database
    Logoff = 9,
    /// Commit transaction
    Commit = 14,
    /// Rollback transaction
    Rollback = 15,
    /// Reexecute and fetch
    ReexecuteAndFetch = 78,
    /// Execute statement
    Execute = 94,
    /// LOB operation
    LobOp = 96,
    /// TPC transaction switch
    TpcTxnSwitch = 103,
    /// TPC transaction change state
    TpcTxnChangeState = 104,
    /// Close cursors
    CloseCursors = 105,
    /// Authentication phase one
    AuthPhaseOne = 118,
    /// Authentication phase two
    AuthPhaseTwo = 115,
    /// AQ enqueue
    AqEnq = 121,
    /// AQ dequeue
    AqDeq = 122,
    /// Direct path prepare
    DirectPathPrepare = 128,
    /// Direct path load stream
    DirectPathLoadStream = 129,
    /// Direct path operation
    DirectPathOp = 130,
    /// Set end-to-end attribute
    SetEndToEndAttr = 135,
    /// Array AQ
    ArrayAq = 145,
    /// Ping
    Ping = 147,
    /// Set schema
    SetSchema = 152,
    /// Session get
    SessionGet = 162,
    /// Session release
    SessionRelease = 163,
    /// Session state
    SessionState = 176,
    /// Pipeline begin
    PipelineBegin = 199,
    /// Pipeline end
    PipelineEnd = 200,
}

// =============================================================================
// Control Packet Types
// =============================================================================

/// Control packet type constants
#[allow(missing_docs)]
pub mod control_type {
    pub const INBAND_NOTIFICATION: u16 = 8;
    pub const RESET_OOB: u16 = 9;
}

// =============================================================================
// Protocol Versions
// =============================================================================

/// Protocol version constants
pub mod version {
    /// Desired protocol version to request
    pub const DESIRED: u16 = 319;
    /// Minimum protocol version we support
    pub const MINIMUM: u16 = 300;
    /// Minimum accepted version (Oracle 12.1)
    pub const MIN_ACCEPTED: u16 = 315;
    /// Minimum version supporting large SDU
    pub const MIN_LARGE_SDU: u16 = 315;
    /// Minimum version supporting OOB check
    pub const MIN_OOB_CHECK: u16 = 318;
    /// Minimum version supporting end of response
    pub const MIN_END_OF_RESPONSE: u16 = 319;
}

// =============================================================================
// Connection Constants
// =============================================================================

/// Connection-related constants
pub mod connection {
    /// Default SDU (Session Data Unit) size
    pub const DEFAULT_SDU: u16 = 8192;
    /// Default TDU (Transport Data Unit) size
    pub const DEFAULT_TDU: u16 = 65535;
    /// Protocol characteristics flags
    pub const PROTOCOL_CHARACTERISTICS: u16 = 0x4f98;
    /// Check OOB flag
    pub const CHECK_OOB: u32 = 0x01;
    /// Maximum connect data that fits in first packet
    pub const MAX_CONNECT_DATA: u16 = 230;
}

// =============================================================================
// Service Options (GSO = Global Service Options)
// =============================================================================

/// Service options flags (GSO = Global Service Options)
#[allow(missing_docs)]
pub mod service_options {
    pub const DONT_CARE: u16 = 0x0001;
    pub const CAN_RECV_ATTENTION: u16 = 0x0400;
}

// =============================================================================
// NSI (Network Session Interface) Flags
// =============================================================================

/// NSI (Network Session Interface) flags
#[allow(missing_docs)]
pub mod nsi_flags {
    pub const DISABLE_NA: u8 = 0x04;
    pub const NA_REQUIRED: u8 = 0x10;
    pub const SUPPORT_SECURITY_RENEG: u8 = 0x80;
}

// =============================================================================
// Accept Flags
// =============================================================================

/// Connection accept flags
#[allow(missing_docs)]
pub mod accept_flags {
    pub const CHECK_OOB: u32 = 0x00000001;
    pub const FAST_AUTH: u32 = 0x10000000;
    pub const HAS_END_OF_RESPONSE: u32 = 0x02000000;
}

// =============================================================================
// Authentication Modes
// =============================================================================

/// Authentication mode flags
#[allow(missing_docs)]
pub mod auth_mode {
    pub const LOGON: u32 = 0x00000001;
    pub const CHANGE_PASSWORD: u32 = 0x00000002;
    pub const SYSDBA: u32 = 0x00000020;
    pub const SYSOPER: u32 = 0x00000040;
    pub const PRELIM: u32 = 0x00000080;
    pub const WITH_PASSWORD: u32 = 0x00000100;
    pub const SYSASM: u32 = 0x00400000;
    pub const SYSBKP: u32 = 0x01000000;
    pub const SYSDGD: u32 = 0x02000000;
    pub const SYSKMT: u32 = 0x04000000;
    pub const SYSRAC: u32 = 0x08000000;
    pub const IAM_TOKEN: u32 = 0x20000000;
}

// =============================================================================
// Verifier Types (for authentication)
// =============================================================================

/// Authentication verifier type constants
#[allow(missing_docs)]
pub mod verifier_type {
    pub const V11G_1: u32 = 0xb152;
    pub const V11G_2: u32 = 0x1b25;
    pub const V12C: u32 = 0x4815;
}

// =============================================================================
// Character Sets
// =============================================================================

/// Character set ID constants
#[allow(missing_docs)]
pub mod charset {
    pub const AL16UTF8: u16 = 208;
    pub const UTF8: u16 = 873;
    pub const UTF16: u16 = 2000;
}

// =============================================================================
// Compile-Time Capability Indices (CCAP)
// =============================================================================

/// Compile-time capability index constants
#[allow(missing_docs)]
pub mod ccap_index {
    pub const SQL_VERSION: usize = 0;
    pub const LOGON_TYPES: usize = 4;
    pub const FEATURE_BACKPORT: usize = 5;
    pub const FIELD_VERSION: usize = 7;
    pub const SERVER_DEFINE_CONV: usize = 8;
    pub const DEQUEUE_WITH_SELECTOR: usize = 9;
    pub const TTC1: usize = 15;
    pub const OCI1: usize = 16;
    pub const TDS_VERSION: usize = 17;
    pub const RPC_VERSION: usize = 18;
    pub const RPC_SIG: usize = 19;
    pub const DBF_VERSION: usize = 21;
    pub const LOB: usize = 23;
    pub const TTC2: usize = 26;
    pub const UB2_DTY: usize = 27;
    pub const OCI2: usize = 31;
    pub const CLIENT_FN: usize = 34;
    pub const OCI3: usize = 35;
    pub const TTC3: usize = 37;
    pub const SESS_SIGNATURE_VERSION: usize = 39;
    pub const TTC4: usize = 40;
    pub const LOB2: usize = 42;
    pub const TTC5: usize = 44;
    pub const VECTOR_FEATURES: usize = 52;
    pub const MAX: usize = 53;
}

// =============================================================================
// Compile-Time Capability Values (CCAP)
// =============================================================================

/// Compile-time capability value constants
#[allow(missing_docs)]
pub mod ccap_value {
    pub const SQL_VERSION_MAX: u8 = 6;
    pub const FIELD_VERSION_11_2: u8 = 6;
    pub const FIELD_VERSION_12_1: u8 = 7;
    pub const FIELD_VERSION_12_2: u8 = 8;
    pub const FIELD_VERSION_18_1: u8 = 10;
    pub const FIELD_VERSION_19_1: u8 = 12;
    pub const FIELD_VERSION_21_1: u8 = 16;
    pub const FIELD_VERSION_23_1: u8 = 17;
    pub const FIELD_VERSION_23_4: u8 = 24;
    pub const FIELD_VERSION_MAX: u8 = 24;

    pub const O5LOGON: u8 = 8;
    pub const O5LOGON_NP: u8 = 2;
    pub const O7LOGON: u8 = 32;
    pub const O8LOGON_LONG_IDENTIFIER: u8 = 64;
    pub const O9LOGON_LONG_PASSWORD: u8 = 0x80;

    pub const CTB_IMPLICIT_POOL: u8 = 0x08;
    pub const CTB_OAUTH_MSG_ON_ERR: u8 = 0x10;

    pub const END_OF_CALL_STATUS: u8 = 0x01;
    pub const IND_RCD: u8 = 0x08;
    pub const FAST_BVEC: u8 = 0x20;
    pub const FAST_SESSION_PROPAGATE: u8 = 0x10;
    pub const APP_CTX_PIGGYBACK: u8 = 0x80;

    pub const TDS_VERSION_MAX: u8 = 3;
    pub const RPC_VERSION_MAX: u8 = 7;
    pub const RPC_SIG_VALUE: u8 = 3;
    pub const DBF_VERSION_MAX: u8 = 1;
    pub const CLIENT_FN_MAX: u8 = 12;

    pub const LOB_UB8_SIZE: u8 = 0x01;
    pub const LOB_ENCS: u8 = 0x02;
    pub const LOB_PREFETCH_DATA: u8 = 0x04;
    pub const LOB_TEMP_SIZE: u8 = 0x08;
    pub const LOB_PREFETCH_LENGTH: u8 = 0x40;
    pub const LOB_12C: u8 = 0x80;

    pub const LOB2_QUASI: u8 = 0x01;
    pub const LOB2_2GB_PREFETCH: u8 = 0x04;

    pub const DRCP: u8 = 0x10;
    pub const ZLNP: u8 = 0x04;
    pub const INBAND_NOTIFICATION: u8 = 0x04;
    pub const EXPLICIT_BOUNDARY: u8 = 0x40;
    pub const END_OF_REQUEST: u8 = 0x20;

    pub const LTXID: u8 = 0x08;
    pub const IMPLICIT_RESULTS: u8 = 0x10;
    pub const BIG_CHUNK_CLR: u8 = 0x20;
    pub const KEEP_OUT_ORDER: u8 = 0x80;

    // TTC5 flags
    pub const VECTOR_SUPPORT: u8 = 0x08;
    pub const TOKEN_SUPPORTED: u8 = 0x02;
    pub const PIPELINING_SUPPORT: u8 = 0x04;
    pub const PIPELINING_BREAK: u8 = 0x10;
    pub const SESSIONLESS_TXNS: u8 = 0x20;

    // Vector features
    pub const VECTOR_FEATURE_BINARY: u8 = 0x01;
    pub const VECTOR_FEATURE_SPARSE: u8 = 0x02;

    // OCI3 flags
    pub const OCI3_OCSSYNC: u8 = 0x20;
}

// =============================================================================
// Runtime Capability Indices (RCAP)
// =============================================================================

/// Runtime capability index constants
#[allow(missing_docs)]
pub mod rcap_index {
    pub const COMPAT: usize = 0;
    pub const TTC: usize = 6;
    pub const MAX: usize = 11;
}

// =============================================================================
// Runtime Capability Values (RCAP)
// =============================================================================

/// Runtime capability value constants
#[allow(missing_docs)]
pub mod rcap_value {
    pub const COMPAT_81: u8 = 2;
    pub const TTC_ZERO_COPY: u8 = 0x01;
    pub const TTC_32K: u8 = 0x04;
    pub const TTC_SESSION_STATE_OPS: u8 = 0x10;
}

// =============================================================================
// Encoding Flags
// =============================================================================

/// Character encoding flags
#[allow(missing_docs)]
pub mod encoding {
    pub const MULTI_BYTE: u8 = 0x01;
    pub const CONV_LENGTH: u8 = 0x02;
}

// =============================================================================
// TNS Length Indicators
// =============================================================================

/// TNS length indicator constants
pub mod length {
    /// Maximum length that fits in a single byte
    pub const MAX_SHORT: u8 = 252;
    /// Escape character for special values
    pub const ESCAPE_CHAR: u8 = 253;
    /// Indicates a long (multi-byte) length follows
    pub const LONG_INDICATOR: u8 = 254;
    /// Indicates NULL value
    pub const NULL_INDICATOR: u8 = 255;
}

// =============================================================================
// Execute Options
// =============================================================================

/// Execute option flags
#[allow(missing_docs)]
pub mod exec_option {
    pub const PARSE: u32 = 0x01;
    pub const BIND: u32 = 0x08;
    pub const DEFINE: u32 = 0x10;
    pub const EXECUTE: u32 = 0x20;
    pub const FETCH: u32 = 0x40;
    pub const COMMIT: u32 = 0x100;
    pub const COMMIT_REEXECUTE: u32 = 0x01;
    pub const PLSQL_BIND: u32 = 0x400;
    pub const NOT_PLSQL: u32 = 0x8000;
    pub const DESCRIBE: u32 = 0x20000;
    pub const NO_COMPRESSED_FETCH: u32 = 0x40000;
    pub const BATCH_ERRORS: u32 = 0x80000;
}

// =============================================================================
// Execute Flags
// =============================================================================

/// Execute flags for statement execution
#[allow(missing_docs)]
pub mod exec_flags {
    pub const DML_ROWCOUNTS: u32 = 0x4000;
    pub const IMPLICIT_RESULTSET: u32 = 0x8000;
    pub const NO_CANCEL_ON_EOF: u32 = 0x80;
    pub const SCROLLABLE: u32 = 0x02;
}

// =============================================================================
// Fetch Orientation (for scrollable cursors)
// =============================================================================

/// Fetch orientation for scrollable cursor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum FetchOrientation {
    /// Fetch current row
    Current = 0x01,
    /// Fetch next row (default)
    #[default]
    Next = 0x02,
    /// Fetch first row
    First = 0x04,
    /// Fetch last row
    Last = 0x08,
    /// Fetch previous row
    Prior = 0x10,
    /// Fetch absolute position
    Absolute = 0x20,
    /// Fetch relative to current position
    Relative = 0x40,
}

// =============================================================================
// Bind Directions
// =============================================================================

/// Bind parameter direction constants (wire format values)
pub mod bind_dir {
    /// Output only parameter (server writes, client reads)
    pub const OUTPUT: u8 = 16;
    /// Input only parameter (client writes, server reads)
    pub const INPUT: u8 = 32;
    /// Input/Output parameter (bidirectional)
    pub const INPUT_OUTPUT: u8 = 48;
}

// =============================================================================
// Oracle Data Types (ORA_TYPE_NUM)
// =============================================================================

/// Oracle internal data type numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OracleType {
    /// VARCHAR2 string type
    Varchar = 1,
    /// NUMBER type
    Number = 2,
    /// BINARY_INTEGER (PL/SQL)
    BinaryInteger = 3,
    /// LONG string type
    Long = 8,
    /// ROWID
    Rowid = 11,
    /// DATE type
    Date = 12,
    /// RAW binary type
    Raw = 23,
    /// LONG RAW binary type
    LongRaw = 24,
    /// CHAR fixed-length string
    Char = 96,
    /// BINARY_FLOAT
    BinaryFloat = 100,
    /// BINARY_DOUBLE
    BinaryDouble = 101,
    /// REF CURSOR
    Cursor = 102,
    /// User-defined object type
    Object = 109,
    /// CLOB
    Clob = 112,
    /// BLOB
    Blob = 113,
    /// BFILE
    Bfile = 114,
    /// JSON (21c+)
    Json = 119,
    /// VECTOR (23ai)
    Vector = 127,
    /// TIMESTAMP
    Timestamp = 180,
    /// TIMESTAMP WITH TIME ZONE
    TimestampTz = 181,
    /// INTERVAL YEAR TO MONTH
    IntervalYm = 182,
    /// INTERVAL DAY TO SECOND
    IntervalDs = 183,
    /// UROWID
    Urowid = 208,
    /// TIMESTAMP WITH LOCAL TIME ZONE
    TimestampLtz = 231,
    /// BOOLEAN (23c+)
    Boolean = 252,
}

impl OracleType {
    /// Check if this type is a LOB type that requires special define handling
    pub fn is_lob(&self) -> bool {
        matches!(
            self,
            OracleType::Clob | OracleType::Blob | OracleType::Bfile | OracleType::Json | OracleType::Vector
        )
    }

    /// Check if this type requires no prefetch (data must be fetched separately)
    pub fn requires_no_prefetch(&self) -> bool {
        matches!(
            self,
            OracleType::Clob | OracleType::Blob | OracleType::Json | OracleType::Vector
        )
    }
}

impl TryFrom<u8> for OracleType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OracleType::Varchar),
            2 => Ok(OracleType::Number),
            3 => Ok(OracleType::BinaryInteger),
            8 => Ok(OracleType::Long),
            11 => Ok(OracleType::Rowid),
            12 => Ok(OracleType::Date),
            23 => Ok(OracleType::Raw),
            24 => Ok(OracleType::LongRaw),
            96 => Ok(OracleType::Char),
            100 => Ok(OracleType::BinaryFloat),
            101 => Ok(OracleType::BinaryDouble),
            102 => Ok(OracleType::Cursor),
            109 => Ok(OracleType::Object),
            112 => Ok(OracleType::Clob),
            113 => Ok(OracleType::Blob),
            114 => Ok(OracleType::Bfile),
            119 => Ok(OracleType::Json),
            127 => Ok(OracleType::Vector),
            180 => Ok(OracleType::Timestamp),
            181 => Ok(OracleType::TimestampTz),
            182 => Ok(OracleType::IntervalYm),
            183 => Ok(OracleType::IntervalDs),
            208 => Ok(OracleType::Urowid),
            231 => Ok(OracleType::TimestampLtz),
            252 => Ok(OracleType::Boolean),
            _ => Err(crate::error::Error::InvalidOracleType(value)),
        }
    }
}

// =============================================================================
// Character Set Form (CSFRM)
// =============================================================================

/// Character set form (CSFRM) constants
pub mod csfrm {
    /// Implicit charset (database charset)
    pub const IMPLICIT: u8 = 1;
    /// NCHAR charset
    pub const NCHAR: u8 = 2;
}

// =============================================================================
// Miscellaneous Constants
// =============================================================================

/// Maximum length for LONG/LONG RAW columns
pub const MAX_LONG_LENGTH: u32 = 0x7FFFFFFF;

/// Maximum length for UROWID
pub const MAX_UROWID_LENGTH: u32 = 5267;

/// Bind indicator flags
#[allow(missing_docs)]
pub mod bind_flags {
    pub const USE_INDICATORS: u8 = 0x01;
    pub const ARRAY: u8 = 0x40;
}

/// Bind parameter direction (IN, OUT, IN OUT)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum BindDirection {
    /// Output only parameter (server writes, client reads)
    Output = 16,
    /// Input only parameter (client writes, server reads) - default
    #[default]
    Input = 32,
    /// Input/Output parameter (bidirectional)
    InputOutput = 48,
}

impl BindDirection {
    /// Check if this direction includes input (IN or IN OUT)
    pub fn is_input(&self) -> bool {
        matches!(self, BindDirection::Input | BindDirection::InputOutput)
    }

    /// Check if this direction includes output (OUT or IN OUT)
    pub fn is_output(&self) -> bool {
        matches!(self, BindDirection::Output | BindDirection::InputOutput)
    }

    /// Create from wire value
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            16 => Some(BindDirection::Output),
            32 => Some(BindDirection::Input),
            48 => Some(BindDirection::InputOutput),
            _ => None,
        }
    }
}

impl TryFrom<u8> for BindDirection {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        BindDirection::from_wire(value)
            .ok_or_else(|| crate::error::Error::Protocol(format!("Invalid bind direction: {}", value)))
    }
}

/// LOB-related flags and constants
#[allow(missing_docs)]
pub mod lob_flags {
    /// LOB prefetch flag for cont_flag field
    pub const PREFETCH: u64 = 0x2000000;

    // LOB locator offsets
    pub const LOC_OFFSET_FLAG_1: usize = 4;
    pub const LOC_OFFSET_FLAG_3: usize = 6;
    pub const LOC_OFFSET_FLAG_4: usize = 7;
    pub const LOC_FIXED_OFFSET: usize = 16;
    pub const QLOCATOR_VERSION: u8 = 4;

    // LOB locator flags (byte 1 at offset 4)
    pub const LOC_FLAGS_BLOB: u8 = 0x01;
    pub const LOC_FLAGS_VALUE_BASED: u8 = 0x20;
    pub const LOC_FLAGS_ABSTRACT: u8 = 0x40;

    // LOB locator flags (byte 2 at offset 5)
    pub const LOC_FLAGS_INIT: u8 = 0x08;

    // LOB locator flags (byte 4 at offset 7)
    pub const LOC_FLAGS_TEMP: u8 = 0x01;
    pub const LOC_FLAGS_VAR_LENGTH_CHARSET: u8 = 0x80;

    // LOB open modes
    pub const OPEN_READ_WRITE: u8 = 2;
    pub const OPEN_READ_ONLY: u8 = 11;

    // LOB buffer size (for locator metadata)
    pub const BUFFER_SIZE: u32 = 112;
}

/// LOB operation codes (for function code 96)
#[allow(missing_docs)]
pub mod lob_op {
    pub const GET_LENGTH: u32 = 0x0001;
    pub const READ: u32 = 0x0002;
    pub const TRIM: u32 = 0x0020;
    pub const WRITE: u32 = 0x0040;
    pub const GET_CHUNK_SIZE: u32 = 0x4000;
    pub const CREATE_TEMP: u32 = 0x0110;
    pub const FREE_TEMP: u32 = 0x0111;
    pub const OPEN: u32 = 0x8000;
    pub const CLOSE: u32 = 0x10000;
    pub const IS_OPEN: u32 = 0x11000;
    pub const ARRAY: u32 = 0x80000;
    pub const FILE_EXISTS: u32 = 0x0800;
    pub const FILE_OPEN: u32 = 0x0100;
    pub const FILE_CLOSE: u32 = 0x0200;
    pub const FILE_ISOPEN: u32 = 0x0400;
}

/// LOB duration constants
pub mod lob_duration {
    /// Session duration for temporary LOBs
    pub const SESSION: u64 = 10;
}

// =============================================================================
// Database Object / Collection Constants
// =============================================================================

/// Object/Collection flags and constants
pub mod obj_flags {
    /// Object is version 8.1 format
    pub const IS_VERSION_81: u8 = 0x80;
    /// Object is degenerate (no data)
    pub const IS_DEGENERATE: u8 = 0x10;
    /// Object is a collection
    pub const IS_COLLECTION: u8 = 0x08;
    /// No prefix segment
    pub const NO_PREFIX_SEG: u8 = 0x04;
    /// Current image version
    pub const IMAGE_VERSION: u8 = 1;
    /// Maximum short length for pickle encoding
    pub const MAX_SHORT_LENGTH: u8 = 245;
    /// Atomic NULL indicator
    pub const ATOMIC_NULL: u8 = 253;
    /// Non-null OID flag
    pub const NON_NULL_OID: u8 = 0x02;
    /// Has extent OID
    pub const HAS_EXTENT_OID: u8 = 0x08;
    /// Top level object
    pub const TOP_LEVEL: u8 = 0x01;
    /// Has indexes (for associative arrays)
    pub const HAS_INDEXES: u8 = 0x10;
    /// TOID prefix bytes (version/marker)
    pub const TOID_PREFIX: [u8; 2] = [0x00, 0x22];
    /// Extent OID (16 bytes) - appended to TOID after type OID
    pub const EXTENT_OID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
}

/// Collection type codes
pub mod collection_type {
    /// PL/SQL INDEX BY table (associative array)
    pub const PLSQL_INDEX_TABLE: u8 = 1;
    /// Nested table
    pub const NESTED_TABLE: u8 = 2;
    /// VARRAY
    pub const VARRAY: u8 = 3;
}

/// TDS (Type Descriptor Set) type codes for object elements
#[allow(missing_docs)]
pub mod tds_type {
    pub const CHAR: u8 = 1;
    pub const DATE: u8 = 2;
    pub const FLOAT: u8 = 5;
    pub const NUMBER: u8 = 6;
    pub const VARCHAR: u8 = 7;
    pub const BOOLEAN: u8 = 8;
    pub const RAW: u8 = 19;
    pub const TIMESTAMP: u8 = 21;
    pub const TIMESTAMP_TZ: u8 = 23;
    pub const OBJ: u8 = 27;
    pub const COLL: u8 = 28;
    pub const CLOB: u8 = 29;
    pub const BLOB: u8 = 30;
    pub const TIMESTAMP_LTZ: u8 = 33;
    pub const BINARY_FLOAT: u8 = 37;
    pub const BINARY_DOUBLE: u8 = 38;
    pub const START_EMBED_ADT: u8 = 39;
    pub const BINARY_INTEGER: u8 = 47;
    pub const UROWID: u8 = 104;
    pub const INTERVAL_DS: u8 = 119;
    pub const INTERVAL_YM: u8 = 120;
}

// =============================================================================
// Error Codes
// =============================================================================

/// Oracle error code constants
#[allow(missing_docs)]
pub mod error_code {
    pub const INCONSISTENT_DATA_TYPES: u32 = 932;
    pub const VAR_NOT_IN_SELECT_LIST: u32 = 1007;
    pub const NO_DATA_FOUND: u32 = 1403;
    pub const EXCEEDED_IDLE_TIME: u32 = 2396;
    pub const INVALID_SID: u32 = 12505;
    pub const INVALID_SERVICE_NAME: u32 = 12514;
    pub const SESSION_SHUTDOWN: u32 = 12572;
    pub const INBAND_MESSAGE: u32 = 12573;
    pub const ARRAY_DML_ERRORS: u32 = 24381;
    pub const NO_MESSAGES_FOUND: u32 = 25228;
}

// =============================================================================
// Packet Header
// =============================================================================

/// TNS packet header size in bytes
pub const PACKET_HEADER_SIZE: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_conversion() {
        assert_eq!(PacketType::try_from(1).unwrap(), PacketType::Connect);
        assert_eq!(PacketType::try_from(2).unwrap(), PacketType::Accept);
        assert_eq!(PacketType::try_from(6).unwrap(), PacketType::Data);
        assert!(PacketType::try_from(255).is_err());
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(1).unwrap(), MessageType::Protocol);
        assert_eq!(MessageType::try_from(3).unwrap(), MessageType::Function);
        assert_eq!(MessageType::try_from(34).unwrap(), MessageType::FastAuth);
        assert!(MessageType::try_from(255).is_err());
    }

    #[test]
    fn test_packet_type_repr() {
        assert_eq!(PacketType::Connect as u8, 1);
        assert_eq!(PacketType::Accept as u8, 2);
        assert_eq!(PacketType::Data as u8, 6);
    }
}
