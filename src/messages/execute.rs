//! Execute message for SQL statement execution
//!
//! This module implements the execute message used for running SQL statements
//! and PL/SQL blocks on the Oracle server.

use bytes::{BufMut, Bytes, BytesMut};

use crate::buffer::WriteBuffer;
use crate::capabilities::Capabilities;
use crate::constants::{
    ccap_value, exec_flags, exec_option, FunctionCode, MessageType, OracleType, PacketType,
    MAX_LONG_LENGTH, PACKET_HEADER_SIZE,
};
use crate::error::Result;
use crate::row::Value;
use crate::statement::Statement;

/// Options for statement execution
#[derive(Debug, Clone, Default)]
pub struct ExecuteOptions {
    /// Parse the statement
    pub parse: bool,
    /// Execute the statement
    pub execute: bool,
    /// Fetch rows (for queries)
    pub fetch: bool,
    /// Commit after execution
    pub commit: bool,
    /// Define columns (for queries)
    pub define: bool,
    /// Describe only (don't execute)
    pub describe_only: bool,
    /// Enable batch errors
    pub batch_errors: bool,
    /// Enable DML row counts
    pub dml_row_counts: bool,
    /// Scrollable cursor
    pub scrollable: bool,
    /// Scroll operation (fetch from position, don't re-execute)
    pub scroll_operation: bool,
    /// Fetch orientation for scroll operations
    pub fetch_orientation: u32,
    /// Fetch position for scroll operations
    pub fetch_pos: u32,
    /// Number of rows to prefetch
    pub prefetch_rows: u32,
    /// Number of executions (for batch)
    pub num_execs: u32,
}

impl ExecuteOptions {
    /// Create default options for a query
    pub fn for_query(prefetch_rows: u32) -> Self {
        Self {
            parse: true,
            execute: true,
            fetch: prefetch_rows > 0,
            prefetch_rows,
            num_execs: 1,
            ..Default::default()
        }
    }

    /// Create default options for DML
    pub fn for_dml(commit: bool) -> Self {
        Self {
            parse: true,
            execute: true,
            commit,
            num_execs: 1,
            ..Default::default()
        }
    }

    /// Create default options for PL/SQL
    pub fn for_plsql() -> Self {
        Self {
            parse: true,
            execute: true,
            num_execs: 1,
            ..Default::default()
        }
    }

    /// Create options for describe only (parse but don't execute)
    pub fn describe_only() -> Self {
        Self {
            parse: true,
            describe_only: true,
            ..Default::default()
        }
    }

    /// Create options for fetching from a REF CURSOR
    ///
    /// REF CURSORs use an ExecuteMessage with only the FETCH option (no EXECUTE,
    /// no DEFINE, no PARSE). The cursor is already open from the PL/SQL execution,
    /// and Oracle already knows the column types. We just need to fetch rows.
    ///
    /// Per Python's implementation: when `_sql is None` (REF CURSOR case), it uses
    /// ExecuteMessage with options = FETCH only.
    pub fn for_ref_cursor(fetch_size: u32) -> Self {
        Self {
            parse: false,      // Cursor is already parsed by Oracle
            execute: false,    // Don't set EXECUTE flag - cursor is already executed
            fetch: fetch_size > 0,  // Only FETCH flag is needed
            define: false,     // Don't set DEFINE flag - Oracle knows the column types
            prefetch_rows: fetch_size,
            num_execs: fetch_size,  // This becomes the fetch array size
            ..Default::default()
        }
    }
}

/// Metadata for a bind parameter (used for OUT params where we need explicit size)
#[derive(Debug, Clone)]
pub struct BindMetadata {
    /// Oracle type for the parameter
    pub oracle_type: OracleType,
    /// Buffer size for output
    pub buffer_size: u32,
}

/// Execute message for SQL statement execution
#[derive(Debug)]
pub struct ExecuteMessage<'a> {
    /// The statement to execute
    statement: &'a Statement,
    /// Execution options
    options: ExecuteOptions,
    /// Function code (Execute, Reexecute, or ReexecuteAndFetch)
    function_code: FunctionCode,
    /// Bind values for execution (multiple rows for batch execution)
    /// Each inner Vec represents one row of bind values
    batch_bind_values: Vec<Vec<Value>>,
    /// Sequence number for TTC protocol
    sequence_number: u8,
    /// Skip writing RowData values (for PL/SQL pure OUT parameters)
    /// When true, only bind metadata is written without values
    skip_row_data: bool,
    /// Optional explicit bind metadata (for PL/SQL OUT params)
    /// When present, overrides inferred types/sizes from values
    bind_metadata: Option<Vec<BindMetadata>>,
}

impl<'a> ExecuteMessage<'a> {
    /// Create a new execute message
    pub fn new(statement: &'a Statement, options: ExecuteOptions) -> Self {
        // Determine function code based on statement state
        // Per Python: REF CURSORs (sql is empty/None) always use Execute
        let function_code = if statement.cursor_id() == 0
            || !statement.executed()
            || statement.sql().is_empty() // REF CURSOR has no SQL - use Execute
            || statement.is_ddl()
            || statement.binds_changed()
            || options.describe_only
            || statement.requires_define()
            || options.batch_errors
            || options.scrollable
        {
            FunctionCode::Execute
        } else if statement.is_query() && options.prefetch_rows > 0 {
            FunctionCode::ReexecuteAndFetch
        } else {
            FunctionCode::Reexecute
        };

        Self {
            statement,
            options,
            function_code,
            batch_bind_values: Vec::new(),
            sequence_number: 1,
            skip_row_data: false,
            bind_metadata: None,
        }
    }

    /// Set explicit bind metadata (for PL/SQL OUT params)
    ///
    /// This overrides the inferred types/sizes from values. Use this for OUT
    /// parameters where the buffer size needs to be specified explicitly.
    pub fn set_bind_metadata(&mut self, metadata: Vec<BindMetadata>) {
        self.bind_metadata = Some(metadata);
    }

    /// Set whether to skip writing RowData values (for PL/SQL OUT parameters)
    ///
    /// When true, only bind metadata is written without values. This is required
    /// for PL/SQL blocks with OUT-only parameters, where Oracle expects to know
    /// the output types but doesn't need input values.
    pub fn set_skip_row_data(&mut self, skip: bool) {
        self.skip_row_data = skip;
    }

    /// Set the sequence number for TTC protocol
    pub fn set_sequence_number(&mut self, seq: u8) {
        self.sequence_number = seq;
    }

    /// Set bind values for execution (single row)
    pub fn set_bind_values(&mut self, values: Vec<Value>) {
        self.batch_bind_values = vec![values];
    }

    /// Set bind values for batch execution (multiple rows)
    pub fn set_batch_bind_values(&mut self, rows: Vec<Vec<Value>>) {
        self.batch_bind_values = rows;
        // Update num_execs to match batch size
        if !self.batch_bind_values.is_empty() {
            self.options.num_execs = self.batch_bind_values.len() as u32;
        }
    }

    /// Check if there are bind values
    pub fn has_bind_values(&self) -> bool {
        !self.batch_bind_values.is_empty() && !self.batch_bind_values[0].is_empty()
    }

    /// Get the number of bind value rows (batch size)
    pub fn batch_size(&self) -> usize {
        self.batch_bind_values.len()
    }

    /// Build the execute request packet
    pub fn build_request(&self, caps: &Capabilities) -> Result<Bytes> {
        self.build_request_with_sdu(caps, false)
    }

    /// Build the execute request packet with large SDU support
    pub fn build_request_with_sdu(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        let mut buf = WriteBuffer::new();

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        match self.function_code {
            FunctionCode::Execute => self.write_execute_message(&mut buf, caps)?,
            FunctionCode::Reexecute | FunctionCode::ReexecuteAndFetch => {
                self.write_reexecute_message(&mut buf, caps)?
            }
            _ => unreachable!(),
        }

        // Build packet with header
        let payload = buf.freeze();
        let packet_len = PACKET_HEADER_SIZE + payload.len();

        let mut packet = BytesMut::with_capacity(packet_len);

        // Packet header - use 4-byte length for large SDU
        if large_sdu {
            packet.put_u32((packet_len) as u32);
        } else {
            packet.put_u16(packet_len as u16);
            packet.put_u16(0); // Checksum (not used for large SDU)
        }
        packet.put_u8(PacketType::Data as u8);
        packet.put_u8(0); // Flags
        packet.put_u16(0); // Header checksum

        // Payload (includes data flags)
        packet.extend_from_slice(&payload);

        Ok(packet.freeze())
    }

    /// Write a full execute message
    fn write_execute_message(&self, buf: &mut WriteBuffer, caps: &Capabilities) -> Result<()> {
        let stmt = self.statement;
        let opts = &self.options;

        // Build execute options flags
        let mut exec_opts: u32 = 0;
        let mut exec_flgs: u32 = 0;
        // Use bind_info length if available, otherwise use bind_values count
        // Important: don't count binds when requires_define is true (LOB re-execute case)
        // because we write column defines instead of bind params
        let num_params = if stmt.requires_define() {
            0 // No bind params when defining columns
        } else if !stmt.bind_info().is_empty() {
            stmt.bind_info().len() as u32
        } else if self.has_bind_values() {
            self.batch_bind_values[0].len() as u32
        } else {
            0
        };
        if stmt.requires_define() {
            exec_opts |= exec_option::DEFINE;
        } else if !opts.describe_only && !stmt.sql().is_empty() {
            // Only set IMPLICIT_RESULTSET and EXECUTE when we have SQL.
            // REF CURSORs have no SQL and should not set these flags.
            exec_flgs |= exec_flags::IMPLICIT_RESULTSET;
            if opts.execute && !opts.scroll_operation {
                exec_opts |= exec_option::EXECUTE;
            }
        }

        if opts.scrollable {
            exec_flgs |= exec_flags::SCROLLABLE;
            exec_flgs |= exec_flags::NO_CANCEL_ON_EOF;
        }

        if stmt.cursor_id() == 0 || stmt.is_ddl() {
            exec_opts |= exec_option::PARSE;
        }

        // Add FETCH flag for queries or when explicitly requested (e.g., REF CURSOR)
        if opts.describe_only {
            exec_opts |= exec_option::DESCRIBE;
        } else if opts.fetch && opts.prefetch_rows > 0 && !stmt.no_prefetch() {
            exec_opts |= exec_option::FETCH;
        }

        if !stmt.is_plsql() && !opts.describe_only {
            exec_opts |= exec_option::NOT_PLSQL;
        } else if stmt.is_plsql() && num_params > 0 {
            exec_opts |= exec_option::PLSQL_BIND;
        }

        if num_params > 0 && !opts.scroll_operation {
            exec_opts |= exec_option::BIND;
        }

        if opts.batch_errors {
            exec_opts |= exec_option::BATCH_ERRORS;
        }

        if opts.dml_row_counts {
            exec_flgs |= exec_flags::DML_ROWCOUNTS;
        }

        if opts.commit && !opts.describe_only {
            exec_opts |= exec_option::COMMIT;
        }

        // Determine number of iterations (prefetch rows for queries, num_execs for DML)
        let num_iters = if stmt.is_query() {
            opts.prefetch_rows
        } else {
            opts.num_execs
        };

        // Write message header
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(self.function_code as u8)?;
        buf.write_u8(self.sequence_number)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Write execute body
        buf.write_ub4(exec_opts)?; // Execute options
        buf.write_ub4(stmt.cursor_id() as u32)?; // Cursor ID

        // SQL pointer and length
        if stmt.cursor_id() == 0 || stmt.is_ddl() {
            buf.write_u8(1)?; // Pointer (cursor id)
            buf.write_ub4(stmt.sql_bytes().len() as u32)?;
        } else {
            buf.write_u8(0)?; // Pointer (cursor id)
            buf.write_ub4(0)?;
        }

        buf.write_u8(1)?; // Pointer (vector)
        buf.write_ub4(13)?; // al8i4 array length

        buf.write_u8(0)?; // Pointer (al8o4)
        buf.write_u8(0)?; // Pointer (al8o4l)
        buf.write_ub4(0)?; // Prefetch buffer size
        buf.write_ub4(num_iters)?; // Prefetch number of rows
        buf.write_ub4(MAX_LONG_LENGTH)?; // Maximum long size

        // Bind parameters
        if num_params == 0 {
            buf.write_u8(0)?; // Pointer (binds)
            buf.write_ub4(0)?; // Number of binds
        } else {
            buf.write_u8(1)?; // Pointer (binds)
            buf.write_ub4(num_params)?; // Number of binds
        }

        buf.write_u8(0)?; // Pointer (al8app)
        buf.write_u8(0)?; // Pointer (al8txn)
        buf.write_u8(0)?; // Pointer (al8txl)
        buf.write_u8(0)?; // Pointer (al8kv)
        buf.write_u8(0)?; // Pointer (al8kvl)

        // Column defines
        if stmt.requires_define() {
            buf.write_u8(1)?; // Pointer (al8doac)
            buf.write_ub4(stmt.column_count() as u32)?; // Number of defines
        } else {
            buf.write_u8(0)?;
            buf.write_ub4(0)?;
        }

        buf.write_ub4(0)?; // Registration ID
        buf.write_u8(0)?; // Pointer (al8objlist)
        buf.write_u8(1)?; // Pointer (al8objlen)
        buf.write_u8(0)?; // Pointer (al8blv)
        buf.write_ub4(0)?; // al8blvl
        buf.write_u8(0)?; // Pointer (al8dnam)
        buf.write_ub4(0)?; // al8dnaml
        buf.write_ub4(0)?; // al8regid_msb

        // DML row counts
        if opts.dml_row_counts {
            buf.write_u8(1)?; // Pointer (al8pidmlrc)
            buf.write_ub4(opts.num_execs)?; // al8pidmlrcbl
            buf.write_u8(1)?; // Pointer (al8pidmlrcl)
        } else {
            buf.write_u8(0)?; // Pointer (al8pidmlrc)
            buf.write_ub4(0)?; // al8pidmlrcbl
            buf.write_u8(0)?; // Pointer (al8pidmlrcl)
        }

        // Extended fields (12.2+)
        if caps.ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
            buf.write_u8(0)?; // Pointer (al8sqlsig)
            buf.write_ub4(0)?; // SQL signature length
            buf.write_u8(0)?; // Pointer (SQL ID)
            buf.write_ub4(0)?; // Allocated size of SQL ID
            buf.write_u8(0)?; // Pointer (length of SQL ID)
            // Additional fields for 12.2 EXT1+ (TTC field version >= 9)
            if caps.ttc_field_version >= 9 {
                buf.write_u8(0)?; // Pointer (chunk ids)
                buf.write_ub4(0)?; // Number of chunk ids
            }
        }

        // Write SQL if parsing
        if stmt.cursor_id() == 0 || stmt.is_ddl() {
            buf.write_bytes_with_length(Some(stmt.sql_bytes()))?;
            buf.write_ub4(1)?; // al8i4[0] parse
        } else {
            buf.write_ub4(0)?; // al8i4[0] parse
        }

        // Write al8i4 array
        if stmt.is_query() {
            if stmt.cursor_id() == 0 {
                buf.write_ub4(0)?; // al8i4[1] execution count
            } else {
                buf.write_ub4(num_iters)?;
            }
        } else {
            buf.write_ub4(opts.num_execs)?; // al8i4[1] execution count
        }

        buf.write_ub4(0)?; // al8i4[2]
        buf.write_ub4(0)?; // al8i4[3]
        buf.write_ub4(0)?; // al8i4[4]
        buf.write_ub4(0)?; // al8i4[5] SCN (part 1)
        buf.write_ub4(0)?; // al8i4[6] SCN (part 2)
        buf.write_ub4(if stmt.is_query() { 1 } else { 0 })?; // al8i4[7] is query
        buf.write_ub4(0)?; // al8i4[8]
        buf.write_ub4(exec_flgs)?; // al8i4[9] execute flags
        // For scrollable cursors, set fetch_orientation to CURRENT (1) and fetch_pos to 1
        let (fetch_ori, fetch_pos_val) = if opts.scrollable && !opts.scroll_operation {
            (1u32, 1u32)
        } else if opts.scroll_operation {
            (opts.fetch_orientation, opts.fetch_pos)
        } else {
            (0u32, 0u32)
        };
        buf.write_ub4(fetch_ori)?; // al8i4[10] fetch orientation
        buf.write_ub4(fetch_pos_val)?; // al8i4[11] fetch pos
        buf.write_ub4(0)?; // al8i4[12]

        // Write column defines if required (for LOB columns)
        if stmt.requires_define() {
            self.write_column_defines(buf, caps)?;
        } else if self.has_bind_values() {
            // Write bind metadata and values if present (only when not defining)
            self.write_bind_params(buf, caps)?;
        }

        Ok(())
    }

    /// Write column define metadata for LOB columns
    ///
    /// This tells Oracle how we want the column data returned. For LOB columns,
    /// we need to tell Oracle to return LOB locators instead of inline data.
    fn write_column_defines(&self, buf: &mut WriteBuffer, caps: &Capabilities) -> Result<()> {
        use crate::constants::{bind_flags, ccap_value, charset, lob_flags};

        for col in self.statement.columns() {
            let mut ora_type_num = col.oracle_type as u8;
            let mut buffer_size = col.buffer_size;

            // Handle ROWID/UROWID by treating as VARCHAR
            if col.oracle_type == OracleType::Rowid || col.oracle_type == OracleType::Urowid {
                ora_type_num = OracleType::Varchar as u8;
                buffer_size = 4000; // MAX_UROWID_LENGTH
            }

            // Set flags - always use indicators
            let flag = bind_flags::USE_INDICATORS;

            // Set cont_flag for LOB types
            let mut cont_flag: u64 = 0;
            let mut lob_prefetch_length: u32 = 0;

            if col.oracle_type == OracleType::Blob || col.oracle_type == OracleType::Clob {
                cont_flag = lob_flags::PREFETCH;
            } else if col.oracle_type == OracleType::Json {
                cont_flag = lob_flags::PREFETCH;
                buffer_size = 1_000_000; // JSON max length
                lob_prefetch_length = 1_000_000;
            } else if col.oracle_type == OracleType::Vector {
                cont_flag = lob_flags::PREFETCH;
                buffer_size = 1_000_000; // Vector max length
                lob_prefetch_length = 1_000_000;
            }

            // Write column metadata
            buf.write_u8(ora_type_num)?; // Data type
            buf.write_u8(flag)?; // Flags (USE_INDICATORS)
            buf.write_u8(0)?; // Precision (always 0 for defines)
            buf.write_u8(0)?; // Scale (always 0 for defines)
            buf.write_ub4(buffer_size)?; // Buffer size
            buf.write_ub4(0)?; // Max num elements (0 for non-arrays)
            buf.write_ub8(cont_flag)?; // Cont flag (LOB prefetch flag)
            buf.write_ub4(0)?; // OID (0 for non-object types)
            buf.write_ub2(0)?; // Version (0 for non-object types)

            // Charset ID (UTF-8 if character data, 0 otherwise)
            if col.csfrm != 0 {
                buf.write_ub2(charset::UTF8)?;
            } else {
                buf.write_ub2(0)?;
            }

            buf.write_u8(col.csfrm)?; // Character set form
            buf.write_ub4(lob_prefetch_length)?; // LOB prefetch length

            // oaccolid for TTC field version >= 12.2
            if caps.ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
                buf.write_ub4(0)?;
            }
        }

        Ok(())
    }

    /// Write bind parameter metadata and values
    ///
    /// For batch execution, writes metadata once (using first row for types, but
    /// calculating max buffer size across all rows), then writes ROW_DATA marker
    /// and values for each row in the batch.
    fn write_bind_params(&self, buf: &mut WriteBuffer, caps: &Capabilities) -> Result<()> {
        use crate::constants::{bind_flags, ccap_value, charset};
        use crate::types::LobValue;

        /// LOB prefetch flag constant (TNS_LOB_PREFETCH_FLAG from Python)
        const LOB_PREFETCH_FLAG: u64 = 0x2000000;

        // Use first row for metadata types (all rows have same schema)
        let first_row = match self.batch_bind_values.first() {
            Some(row) => row,
            None => return Ok(()), // No values to write
        };

        let num_params = first_row.len();

        // Calculate max buffer sizes across all rows for each column
        let mut max_sizes: Vec<u32> = vec![0; num_params];
        for row in &self.batch_bind_values {
            for (col_idx, value) in row.iter().enumerate() {
                let size = match value {
                    Value::String(s) => s.len() as u32,
                    Value::Bytes(b) => b.len() as u32,
                    Value::Json(json) => serde_json::to_string(json).map(|s| s.len() as u32).unwrap_or(100),
                    Value::Vector(vec) => (vec.dimensions() * 8) as u32, // Estimate: 8 bytes per dimension max
                    _ => 0, // Fixed-size types don't need max calculation
                };
                if size > max_sizes[col_idx] {
                    max_sizes[col_idx] = size;
                }
            }
        }

        // Write metadata for each bind parameter
        for (col_idx, value) in first_row.iter().enumerate() {
            // Use explicit metadata if provided, otherwise infer from value
            let (oracle_type, buffer_size, csfrm, cont_flag) = if let Some(ref metadata) = self.bind_metadata {
                // Use explicit metadata (for PL/SQL OUT params)
                if col_idx < metadata.len() {
                    let meta = &metadata[col_idx];
                    let csfrm = match meta.oracle_type {
                        OracleType::Varchar | OracleType::Char | OracleType::Long |
                        OracleType::Clob | OracleType::Json => 1u8,
                        _ => 0u8,
                    };
                    let cont_flag = match meta.oracle_type {
                        OracleType::Clob | OracleType::Blob | OracleType::Json | OracleType::Vector => LOB_PREFETCH_FLAG,
                        _ => 0u64,
                    };
                    (meta.oracle_type, meta.buffer_size, csfrm, cont_flag)
                } else {
                    // Fallback to inference if metadata list is too short
                    self.infer_bind_metadata(value, max_sizes[col_idx])
                }
            } else {
                // Infer from value
                self.infer_bind_metadata(value, max_sizes[col_idx])
            };

            // Write bind metadata (oraub8 format per Python reference)
            buf.write_u8(oracle_type as u8)?;           // Data type (byte 0)
            buf.write_u8(bind_flags::USE_INDICATORS)?;  // Flags (byte 1)
            buf.write_u8(0)?;                           // Precision (byte 2) - always 0
            buf.write_u8(0)?;                           // Scale (byte 3) - always 0
            buf.write_ub4(buffer_size)?;                // Buffer size (bytes 4-7)
            buf.write_ub4(0)?;                          // Max num elements (bytes 8-11)
            buf.write_ub8(cont_flag)?;                  // Cont flag (bytes 12-19)

            // For Object types, write OID + version differently per Python base.pyx:1388-1395
            // Object types write: ub4(oid_len) + bytes_with_length(oid) + ub4(version)
            // Non-object types write: ub4(0) + ub2(0)
            let is_object = oracle_type == OracleType::Object;
            if is_object {
                // For collections/objects, try to extract the type OID from the value
                let type_oid: Option<&[u8]> = if let Value::Collection(ref coll) = value {
                    coll.get("_type_oid").and_then(|v| v.as_bytes())
                } else {
                    None
                };

                if let Some(oid) = type_oid {
                    // Write the type OID
                    buf.write_ub4(oid.len() as u32)?;       // OID length
                    buf.write_bytes_with_length(Some(oid))?;  // OID bytes with length
                    buf.write_ub4(0)?;                      // Version (ub4 for objects)
                } else {
                    // No OID available - write zeros
                    buf.write_ub4(0)?;                      // OID length = 0
                    buf.write_ub4(0)?;                      // Version (ub4 for objects)
                }
            } else {
                buf.write_ub4(0)?;                          // OID length (bytes 20-23)
                buf.write_ub2(0)?;                          // Version (bytes 24-25)
            }

            // Charset ID - UTF8 if character data (csfrm != 0)
            if csfrm != 0 {
                buf.write_ub2(charset::UTF8)?;          // Charset ID (bytes 26-27)
            } else {
                buf.write_ub2(0)?;
            }

            buf.write_u8(csfrm)?;                       // Character set form (byte 28)
            buf.write_ub4(0)?;                          // LOB prefetch length (bytes 29-32)

            // oaccolid for TTC field version >= 12.2
            if caps.ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
                buf.write_ub4(0)?;                      // oaccolid (bytes 33-36)
            }
        }

        // Write bind values for each row in the batch (unless skip_row_data is set)
        // For PL/SQL OUT-only parameters, we skip RowData - Oracle just needs metadata
        if !self.skip_row_data {
            // Each row is prefixed with a ROW_DATA marker
            for row in &self.batch_bind_values {
                buf.write_u8(MessageType::RowData as u8)?;
                for value in row {
                    self.write_bind_value(buf, value)?;
                }
            }
        }

        Ok(())
    }

    /// Infer bind metadata from a value and max size
    fn infer_bind_metadata(&self, value: &Value, max_size: u32) -> (OracleType, u32, u8, u64) {
        use crate::types::LobValue;

        const LOB_PREFETCH_FLAG: u64 = 0x2000000;

        match value {
            Value::Null => (OracleType::Varchar, 1u32, 1u8, 0u64), // Use VARCHAR for NULL
            Value::Integer(_) => (OracleType::Number, 22, 0, 0),
            Value::Float(_) => (OracleType::BinaryDouble, 8, 0, 0),
            Value::String(_) => {
                let size = std::cmp::max(max_size, 1);
                (OracleType::Varchar, size, 1, 0) // csfrm=1 for character data
            }
            Value::Bytes(_) => {
                let size = std::cmp::max(max_size, 1);
                (OracleType::Raw, size, 0, 0)
            }
            Value::Boolean(_) => (OracleType::Boolean, 1, 0, 0),
            Value::Number(_) => (OracleType::Number, 22, 0, 0),
            Value::Timestamp(_) => (OracleType::Timestamp, 13, 0, 0),
            Value::Date(_) => (OracleType::Date, 7, 0, 0),
            Value::RowId(_) => (OracleType::Varchar, 18, 1, 0), // ROWID as VARCHAR
            Value::Lob(lob_value) => {
                // Determine LOB type (CLOB vs BLOB)
                let oracle_type = match lob_value {
                    LobValue::Locator(loc) => loc.oracle_type(),
                    _ => OracleType::Clob, // Default to CLOB
                };
                // LOBs use cont_flag = LOB_PREFETCH_FLAG
                // buffer_size = buffer_size_factor (112 for CLOB, 112 for BLOB)
                let csfrm = if oracle_type == OracleType::Blob { 0 } else { 1 };
                (oracle_type, 112, csfrm, LOB_PREFETCH_FLAG)
            }
            Value::Json(_) => {
                // JSON is encoded as OSON and bound as JSON type
                // Use LOB_PREFETCH_FLAG for prefetch behavior
                let size = std::cmp::max(max_size, 100);
                (OracleType::Json, size, 1, LOB_PREFETCH_FLAG)
            }
            Value::Vector(_) => {
                // VECTOR is bound like a LOB with prefetch
                // Use LOB_PREFETCH_FLAG for prefetch behavior
                let size = std::cmp::max(max_size, 100);
                (OracleType::Vector, size, 0, LOB_PREFETCH_FLAG)
            }
            Value::Cursor(_) => {
                // REF CURSOR - used for PL/SQL cursor parameters
                (OracleType::Cursor, 0, 0, 0)
            }
            Value::Collection(_) => {
                // Collection (VARRAY, Nested Table) - bound as Object type
                // TODO: Full implementation requires type descriptor with OID
                (OracleType::Object, 0, 0, 0)
            }
        }
    }

    /// Write a single bind value
    fn write_bind_value(&self, buf: &mut WriteBuffer, value: &Value) -> Result<()> {
        use crate::types::{encode_binary_double, encode_oracle_number};

        match value {
            Value::Null => {
                buf.write_u8(0)?; // NULL indicator
            }
            Value::Integer(n) => {
                // Encode as Oracle NUMBER format
                let encoded = encode_oracle_number(&n.to_string())?;
                buf.write_u8(encoded.len() as u8)?;
                buf.write_bytes(&encoded)?;
            }
            Value::Float(f) => {
                // Write as Oracle binary double (8 bytes)
                let encoded = encode_binary_double(*f);
                buf.write_u8(8)?;
                buf.write_bytes(&encoded)?;
            }
            Value::Number(n) => {
                // Encode OracleNumber to wire format
                let encoded = encode_oracle_number(n.as_str())?;
                buf.write_u8(encoded.len() as u8)?;
                buf.write_bytes(&encoded)?;
            }
            Value::String(s) => {
                let bytes = s.as_bytes();
                if bytes.is_empty() {
                    buf.write_u8(0)?; // Empty string = NULL in Oracle
                } else if bytes.len() <= 252 {
                    buf.write_u8(bytes.len() as u8)?;
                    buf.write_bytes(bytes)?;
                } else {
                    buf.write_u8(254)?; // Long form indicator
                    buf.write_ub4(bytes.len() as u32)?;
                    buf.write_bytes(bytes)?;
                }
            }
            Value::Bytes(b) => {
                if b.is_empty() {
                    buf.write_u8(0)?;
                } else if b.len() <= 252 {
                    buf.write_u8(b.len() as u8)?;
                    buf.write_bytes(b)?;
                } else {
                    buf.write_u8(254)?;
                    buf.write_ub4(b.len() as u32)?;
                    buf.write_bytes(b)?;
                }
            }
            Value::Boolean(b) => {
                // Oracle Boolean encoding: escape char + value
                // false = 0x02 0x00, true = 0x02 0x01, null = 0xC0 0x01
                buf.write_u8(0x02)?; // Length = 2 bytes
                buf.write_u8(if *b { 0x01 } else { 0x00 })?;
            }
            Value::Timestamp(ts) => {
                // Write as Oracle timestamp
                let bytes = ts.to_oracle_bytes();
                buf.write_u8(bytes.len() as u8)?;
                buf.write_bytes(&bytes)?;
            }
            Value::Date(d) => {
                // Write as Oracle date (7 bytes)
                let bytes = d.to_oracle_bytes();
                buf.write_u8(bytes.len() as u8)?;
                buf.write_bytes(&bytes)?;
            }
            Value::RowId(r) => {
                // Write ROWID as string
                match r.to_string() {
                    Some(s) => {
                        let bytes = s.as_bytes();
                        buf.write_u8(bytes.len() as u8)?;
                        buf.write_bytes(bytes)?;
                    }
                    None => {
                        buf.write_u8(0)?; // NULL for invalid ROWID
                    }
                }
            }
            Value::Lob(lob_value) => {
                use crate::types::LobValue;

                match lob_value {
                    LobValue::Locator(locator) => {
                        // Write LOB locator
                        // Format: UB4(locator_len) + length-prefixed locator bytes
                        let locator_bytes = locator.locator_bytes();
                        buf.write_ub4(locator_bytes.len() as u32)?;
                        buf.write_bytes_with_length(Some(locator_bytes))?;
                    }
                    LobValue::Inline(_) | LobValue::Empty | LobValue::Null => {
                        // For non-locator LOBs, write as NULL
                        // To bind inline data to a LOB column, use a temporary LOB instead
                        buf.write_u8(0)?;
                    }
                }
            }
            Value::Json(json) => {
                use crate::types::OsonEncoder;

                // Encode JSON to OSON format
                match OsonEncoder::encode(json) {
                    Ok(oson_bytes) => {
                        let data_len = oson_bytes.len() as u64;

                        // Write QLocator (40 bytes) - LOB-like descriptor for JSON data
                        // QLocator constants
                        const QLOCATOR_LEN: u32 = 40;
                        const QLOCATOR_VERSION: u16 = 4;
                        const LOB_LOC_FLAGS_BLOB: u8 = 0x01;
                        const LOB_LOC_FLAGS_VALUE_BASED: u8 = 0x20;
                        const LOB_LOC_FLAGS_ABSTRACT: u8 = 0x40;
                        const LOB_LOC_FLAGS_INIT: u8 = 0x08;

                        buf.write_ub4(QLOCATOR_LEN)?;           // QLocator length
                        buf.write_u8(QLOCATOR_LEN as u8)?;      // Chunk length
                        buf.write_u16_be(38)?;                  // Length - 2
                        buf.write_u16_be(QLOCATOR_VERSION)?;    // Version
                        buf.write_u8(LOB_LOC_FLAGS_VALUE_BASED | LOB_LOC_FLAGS_BLOB | LOB_LOC_FLAGS_ABSTRACT)?;
                        buf.write_u8(LOB_LOC_FLAGS_INIT)?;      // Flags
                        buf.write_u16_be(0)?;                   // Additional flags
                        buf.write_u16_be(1)?;                   // byt1
                        buf.write_u64_be(data_len)?;            // Data length
                        buf.write_u16_be(0)?;                   // Unused
                        buf.write_u16_be(0)?;                   // csid
                        buf.write_u16_be(0)?;                   // Unused
                        buf.write_u64_be(0)?;                   // Unused
                        buf.write_u64_be(0)?;                   // Unused

                        // Write OSON data with chunked length prefix
                        // Per Python's write_length():
                        // - < 254: single byte
                        // - 254-65535: 254 + 2-byte BE length
                        // - > 65535: 255 + 4-byte BE length
                        let oson_len = oson_bytes.len();
                        if oson_len < 254 {
                            buf.write_u8(oson_len as u8)?;
                        } else if oson_len <= 65535 {
                            buf.write_u8(254)?;
                            buf.write_u16_be(oson_len as u16)?;
                        } else {
                            buf.write_u8(255)?;
                            buf.write_u32_be(oson_len as u32)?;
                        }
                        buf.write_bytes(&oson_bytes)?;
                    }
                    Err(_) => {
                        // If OSON encoding fails, write as NULL
                        buf.write_u8(0)?;
                    }
                }
            }
            Value::Vector(vector) => {
                use crate::types::encode_vector;

                // Encode vector to binary format
                let vector_bytes = encode_vector(vector);
                let data_len = vector_bytes.len() as u64;

                // Write QLocator (40 bytes) - LOB-like descriptor for VECTOR data
                const QLOCATOR_LEN: u32 = 40;
                const QLOCATOR_VERSION: u16 = 4;
                const LOB_LOC_FLAGS_BLOB: u8 = 0x01;
                const LOB_LOC_FLAGS_VALUE_BASED: u8 = 0x20;
                const LOB_LOC_FLAGS_ABSTRACT: u8 = 0x40;
                const LOB_LOC_FLAGS_INIT: u8 = 0x08;

                buf.write_ub4(QLOCATOR_LEN)?;           // QLocator length
                buf.write_u8(QLOCATOR_LEN as u8)?;      // Chunk length
                buf.write_u16_be(38)?;                  // Length - 2
                buf.write_u16_be(QLOCATOR_VERSION)?;    // Version
                buf.write_u8(LOB_LOC_FLAGS_VALUE_BASED | LOB_LOC_FLAGS_BLOB | LOB_LOC_FLAGS_ABSTRACT)?;
                buf.write_u8(LOB_LOC_FLAGS_INIT)?;      // Flags
                buf.write_u16_be(0)?;                   // Additional flags
                buf.write_u16_be(1)?;                   // byt1
                buf.write_u64_be(data_len)?;            // Data length
                buf.write_u16_be(0)?;                   // Unused
                buf.write_u16_be(0)?;                   // csid
                buf.write_u16_be(0)?;                   // Unused
                buf.write_u64_be(0)?;                   // Unused
                buf.write_u64_be(0)?;                   // Unused

                // Write vector data with chunked length prefix
                let vec_len = vector_bytes.len();
                if vec_len < 254 {
                    buf.write_u8(vec_len as u8)?;
                } else if vec_len <= 65535 {
                    buf.write_u8(254)?;
                    buf.write_u16_be(vec_len as u16)?;
                } else {
                    buf.write_u8(255)?;
                    buf.write_u32_be(vec_len as u32)?;
                }
                buf.write_bytes(&vector_bytes)?;
            }
            Value::Cursor(cursor) => {
                // Write cursor parameter (REF CURSOR)
                // Per Python base.pyx:1459-1470:
                // - If cursor_id is 0: write [1, 0] for new cursor
                // - If cursor_id is non-zero: write ub4(1) + ub4(cursor_id) for existing cursor
                let cursor_id = cursor.cursor_id();
                if cursor_id == 0 {
                    buf.write_u8(1)?;
                    buf.write_u8(0)?;
                } else {
                    buf.write_ub4(1)?;
                    buf.write_ub4(cursor_id as u32)?;
                }
            }
            Value::Collection(collection) => {
                // Collection (VARRAY, Nested Table) - encode as pickle format
                // For OUT parameters (empty collection with metadata only), write NULL format:
                // Per Python base.pyx lines 1431-1437
                if collection.elements.is_empty() {
                    // NULL/OUT param format for objects
                    buf.write_ub4(0)?;  // TOID length
                    buf.write_ub4(0)?;  // OID length
                    buf.write_ub4(0)?;  // snapshot length
                    buf.write_ub2(0)?;  // version
                    buf.write_ub4(0)?;  // packed data length
                    buf.write_ub4(crate::constants::obj_flags::TOP_LEVEL as u32)?;  // flags
                } else {
                    // IN param with actual data - encode as full object wire format
                    // Per Python packet.pyx write_dbobject() lines 873-893
                    self.write_collection_with_data(buf, collection)?;
                }
            }
        }
        Ok(())
    }

    /// Write a collection with actual data (IN parameter binding)
    ///
    /// Per Python packet.pyx write_dbobject() lines 873-893:
    /// - TOID: ub4(len) + bytes_with_length (type object ID)
    /// - OID: ub4(0) (object instance ID - null for new objects)
    /// - snapshot: ub4(0)
    /// - version: ub4(0)
    /// - packed_data_len: ub4(len)
    /// - flags: ub4(TOP_LEVEL)
    /// - packed_data: bytes_with_length
    fn write_collection_with_data(
        &self,
        buf: &mut WriteBuffer,
        collection: &crate::dbobject::DbObject,
    ) -> Result<()> {
        use crate::constants::obj_flags;
        use crate::dbobject::{CollectionType, DbObjectType};
        use crate::types::encode_collection;

        // Extract type metadata from the collection
        let type_oid = collection.get("_type_oid")
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| crate::error::Error::Protocol(
                "Collection missing type OID for IN binding".to_string()
            ))?;

        let schema = collection.get("_type_schema")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let name = collection.get("_type_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let element_type_code = collection.get("_element_type")
            .and_then(|v| v.as_i64())
            .and_then(|c| crate::constants::OracleType::try_from(c as u8).ok())
            .unwrap_or(crate::constants::OracleType::Varchar);

        let coll_type_code = collection.get("_collection_type")
            .and_then(|v| v.as_i64())
            .unwrap_or(3); // Default to VARRAY

        let collection_type = match coll_type_code {
            1 => CollectionType::PlsqlIndexTable,
            2 => CollectionType::NestedTable,
            _ => CollectionType::Varray,
        };

        // Build TOID: prefix + flags + type_oid + extent_oid
        // Per Python dbobject.pyx lines 610-612:
        // toid = b'\x00\x22' + bytes([NON_NULL_OID, HAS_EXTENT_OID]) + type_oid + EXTENT_OID
        let mut toid = Vec::with_capacity(4 + type_oid.len() + 16);
        toid.extend_from_slice(&obj_flags::TOID_PREFIX);
        toid.push(obj_flags::NON_NULL_OID);
        toid.push(obj_flags::HAS_EXTENT_OID);
        toid.extend_from_slice(type_oid);
        toid.extend_from_slice(&obj_flags::EXTENT_OID);

        // Create DbObjectType for pickle encoding
        let obj_type = DbObjectType {
            schema: schema.to_string(),
            name: name.to_string(),
            package_name: None,
            is_collection: true,
            collection_type: Some(collection_type),
            element_type: Some(element_type_code),
            element_type_name: None,
            attributes: vec![],
            oid: Some(type_oid.to_vec()),
        };

        // Encode collection data to pickle format
        let packed_data = encode_collection(collection, &obj_type)?;

        // Write TOID
        buf.write_ub4(toid.len() as u32)?;
        buf.write_bytes_with_length(Some(&toid))?;

        // Write OID (null for new objects)
        buf.write_ub4(0)?;

        // Write snapshot (null)
        buf.write_ub4(0)?;

        // Write version
        buf.write_ub4(0)?;

        // Write packed data length
        buf.write_ub4(packed_data.len() as u32)?;

        // Write flags (TOP_LEVEL)
        buf.write_ub4(obj_flags::TOP_LEVEL as u32)?;

        // Write packed data
        buf.write_bytes_with_length(Some(&packed_data))?;

        Ok(())
    }

    /// Write a re-execute message (for previously parsed statements)
    ///
    /// For batch execution with reexecute, we write cursor_id, num_iters, options,
    /// then for each row: ROW_DATA marker + bind values.
    fn write_reexecute_message(&self, buf: &mut WriteBuffer, caps: &Capabilities) -> Result<()> {
        let stmt = self.statement;
        let opts = &self.options;

        let mut options_1: u32 = 0;
        let mut options_2: u32 = 0;

        let num_iters = if self.function_code == FunctionCode::ReexecuteAndFetch {
            options_1 |= exec_option::EXECUTE;
            opts.prefetch_rows
        } else {
            if opts.commit {
                options_2 |= exec_option::COMMIT_REEXECUTE;
            }
            opts.num_execs
        };

        // Write message header
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(self.function_code as u8)?;
        buf.write_u8(self.sequence_number)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Write reexecute body
        buf.write_ub4(stmt.cursor_id() as u32)?;
        buf.write_ub4(num_iters)?;
        buf.write_ub4(options_1)?;
        buf.write_ub4(options_2)?;

        // Write bind parameter values for batch execution
        // For reexecute, we don't write metadata (cursor already knows the types),
        // just ROW_DATA marker + values for each row
        if self.has_bind_values() {
            for row in &self.batch_bind_values {
                buf.write_u8(MessageType::RowData as u8)?;
                for value in row {
                    self.write_bind_value(buf, value)?;
                }
            }
        }

        Ok(())
    }

    /// Get the function code being used
    pub fn function_code(&self) -> FunctionCode {
        self.function_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_options_for_query() {
        let opts = ExecuteOptions::for_query(100);
        assert!(opts.parse);
        assert!(opts.execute);
        assert!(opts.fetch);
        assert_eq!(opts.prefetch_rows, 100);
    }

    #[test]
    fn test_execute_options_for_dml() {
        let opts = ExecuteOptions::for_dml(true);
        assert!(opts.parse);
        assert!(opts.execute);
        assert!(opts.commit);
        assert!(!opts.fetch);
    }

    #[test]
    fn test_execute_message_function_code() {
        let stmt = Statement::new("SELECT * FROM dual");
        let opts = ExecuteOptions::for_query(100);
        let msg = ExecuteMessage::new(&stmt, opts);
        assert_eq!(msg.function_code(), FunctionCode::Execute);
    }

    #[test]
    fn test_execute_message_builds_packet() {
        let stmt = Statement::new("SELECT * FROM dual");
        let opts = ExecuteOptions::for_query(100);
        let msg = ExecuteMessage::new(&stmt, opts);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Check packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);
    }

    #[test]
    fn test_describe_only_options() {
        let stmt = Statement::new("SELECT * FROM dual");
        let opts = ExecuteOptions::describe_only();
        let msg = ExecuteMessage::new(&stmt, opts);
        assert_eq!(msg.function_code(), FunctionCode::Execute);
    }

    // =========================================================================
    // WIRE-LEVEL PROTOCOL TESTS
    // These tests document specific protocol details learned during development.
    // They serve as reference for anyone implementing Oracle/TNS protocols.
    // =========================================================================

    /// TOID (Type Object ID) wire format for collections/objects:
    ///
    /// | Offset | Size | Field          | Value                              |
    /// |--------|------|----------------|------------------------------------|
    /// | 0      | 2    | prefix         | [0x00, 0x22]                       |
    /// | 2      | 1    | flags1         | 0x02 (NON_NULL_OID)                |
    /// | 3      | 1    | flags2         | 0x08 (HAS_EXTENT_OID)              |
    /// | 4      | 16   | type_oid       | From ALL_TYPES.TYPE_OID            |
    /// | 20     | 16   | extent_oid     | Fixed: 00...00 01 00 01            |
    ///
    /// Total TOID size: 36 bytes
    ///
    /// Reference: Python python-oracledb dbobject.pyx lines 610-612
    #[test]
    fn test_wire_toid_construction() {
        use crate::constants::obj_flags;

        // Simulate a type_oid (16 bytes) as returned from database
        let type_oid: [u8; 16] = [
            0x45, 0xFC, 0x24, 0x2B, 0xB8, 0xC9, 0x46, 0x3B,
            0xE0, 0x63, 0x05, 0x00, 0x11, 0xAC, 0x97, 0x82,
        ];

        // Build TOID as we do in write_collection_with_data
        let mut toid = Vec::with_capacity(36);
        toid.extend_from_slice(&obj_flags::TOID_PREFIX);  // [0x00, 0x22]
        toid.push(obj_flags::NON_NULL_OID);               // 0x02
        toid.push(obj_flags::HAS_EXTENT_OID);             // 0x08
        toid.extend_from_slice(&type_oid);                // 16 bytes
        toid.extend_from_slice(&obj_flags::EXTENT_OID);   // 16 bytes

        // Verify structure
        assert_eq!(toid.len(), 36, "TOID must be exactly 36 bytes");
        assert_eq!(&toid[0..2], &[0x00, 0x22], "TOID prefix");
        assert_eq!(toid[2], 0x02, "NON_NULL_OID flag");
        assert_eq!(toid[3], 0x08, "HAS_EXTENT_OID flag");
        assert_eq!(&toid[4..20], &type_oid, "type_oid");
        assert_eq!(&toid[20..36], &obj_flags::EXTENT_OID, "extent_oid");

        // Verify extent_oid has correct value
        assert_eq!(toid[32], 0x00);
        assert_eq!(toid[33], 0x01);
        assert_eq!(toid[34], 0x00);
        assert_eq!(toid[35], 0x01);
    }

    /// Object bind metadata format differs from scalar types:
    ///
    /// For Object/Collection types (OracleType::Object):
    ///   write_ub4(oid_len)              // Length of OID
    ///   write_bytes_with_length(oid)    // OID bytes with TNS length prefix
    ///   write_ub4(version)              // Type version (usually 0)
    ///
    /// For Scalar types:
    ///   write_ub4(0)                    // No OID
    ///   write_ub2(0)                    // Different field size!
    ///
    /// Using ub2 instead of ub4 for version causes protocol errors.
    ///
    /// Reference: Python python-oracledb base.pyx lines 1393-1406
    #[test]
    fn test_wire_object_bind_metadata_uses_ub4_version() {
        use crate::buffer::WriteBuffer;

        // Object type bind metadata format
        let mut obj_meta = WriteBuffer::new();
        let oid = [0x01, 0x02, 0x03]; // Sample OID

        // Object format: ub4(oid_len) + bytes_with_length(oid) + ub4(version)
        obj_meta.write_ub4(oid.len() as u32).unwrap();
        obj_meta.write_bytes_with_length(Some(&oid)).unwrap();
        obj_meta.write_ub4(0).unwrap();  // version as ub4

        // Scalar format (for comparison): ub4(0) + ub2(0)
        let mut scalar_meta = WriteBuffer::new();
        scalar_meta.write_ub4(0).unwrap();
        scalar_meta.write_ub2(0).unwrap();

        // Object metadata is longer due to OID + ub4 version
        assert!(obj_meta.len() > scalar_meta.len(),
            "Object bind metadata includes OID and uses ub4 for version");

        // CRITICAL: TNS variable-length encoding means ub4(0) and ub2(0) each write 1 byte!
        // - write_ub4(0) = 0x00 (single byte)
        // - write_ub2(0) = 0x00 (single byte)
        // This is why using the right function matters - non-zero values encode differently:
        // - write_ub4(300) = [0x02, 0x01, 0x2C] (3 bytes)
        // - write_ub2(300) = [0x02, 0x01, 0x2C] (3 bytes) - same for values up to 65535
        // But for values > 65535, ub4 would use 4 bytes while ub2 would overflow
        assert_eq!(scalar_meta.len(), 2, "Scalar: ub4(0) + ub2(0) = 2 bytes (variable-length encoding)");
    }
}
