//! SQL Statement handling
//!
//! This module provides types for representing and executing SQL statements,
//! including support for bind parameters and result set metadata.

use crate::constants::{BindDirection, OracleType};
use crate::row::Value;
use crate::types::RefCursor;

/// Statement type determined by parsing the SQL
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatementType {
    /// Unknown or unparsed statement
    #[default]
    Unknown,
    /// SELECT query
    Query,
    /// DML: INSERT, UPDATE, DELETE, MERGE
    Dml,
    /// DDL: CREATE, ALTER, DROP, etc.
    Ddl,
    /// PL/SQL block: BEGIN, DECLARE, CALL
    PlSql,
}

/// Metadata for a bind parameter
#[derive(Debug, Clone)]
pub struct BindInfo {
    /// Parameter name (without leading colon)
    pub name: String,
    /// Whether this is a RETURNING INTO bind
    pub is_return_bind: bool,
    /// Oracle type number
    pub oracle_type: Option<OracleType>,
    /// Buffer size
    pub buffer_size: u32,
    /// Precision (for NUMBER)
    pub precision: i16,
    /// Scale (for NUMBER)
    pub scale: i16,
    /// Character set form (1=implicit, 2=nchar)
    pub csfrm: u8,
    /// Bind direction
    pub bind_dir: u8,
    /// Whether this is an array bind
    pub is_array: bool,
    /// Number of array elements
    pub num_elements: u32,
}

impl BindInfo {
    /// Create a new bind parameter with the given name
    pub fn new(name: impl Into<String>, is_return_bind: bool) -> Self {
        Self {
            name: name.into(),
            is_return_bind,
            oracle_type: None,
            buffer_size: 0,
            precision: 0,
            scale: 0,
            csfrm: 0,
            bind_dir: crate::constants::bind_dir::INPUT,
            is_array: false,
            num_elements: 0,
        }
    }
}

/// A bind parameter for PL/SQL execution with direction support
///
/// This struct allows specifying IN, OUT, and IN OUT parameters for PL/SQL calls.
///
/// # Examples
///
/// ```ignore
/// use oracle_rs::{BindParam, BindDirection, OracleType, Value};
///
/// // IN parameter (default)
/// let in_param = BindParam::input(Value::Integer(42));
///
/// // OUT parameter - specify the expected type and size
/// let out_param = BindParam::output(OracleType::Varchar, 100);
///
/// // IN OUT parameter
/// let inout_param = BindParam::input_output(Value::String("hello".into()), 100);
///
/// // Execute PL/SQL
/// let results = conn.execute_plsql(
///     "BEGIN :1 := :2 * 2; END;",
///     &[out_param, in_param]
/// ).await?;
/// ```
#[derive(Debug, Clone)]
pub struct BindParam {
    /// The value (None for pure OUT parameters)
    pub value: Option<Value>,
    /// Parameter direction
    pub direction: BindDirection,
    /// Oracle type (required for OUT parameters)
    pub oracle_type: OracleType,
    /// Buffer size for OUT parameters
    pub buffer_size: u32,
}

impl BindParam {
    /// Create an IN (input) parameter from a value
    pub fn input(value: Value) -> Self {
        let oracle_type = Self::infer_oracle_type(&value);
        Self {
            value: Some(value),
            direction: BindDirection::Input,
            oracle_type,
            buffer_size: 0, // Will be calculated from value
        }
    }

    /// Create an OUT (output) parameter with the expected type and size
    pub fn output(oracle_type: OracleType, buffer_size: u32) -> Self {
        Self {
            value: None,
            direction: BindDirection::Output,
            oracle_type,
            buffer_size,
        }
    }

    /// Create an OUT parameter for a REF CURSOR
    pub fn output_cursor() -> Self {
        Self {
            value: Some(Value::Cursor(RefCursor::new(0, vec![]))), // Placeholder cursor
            direction: BindDirection::Output,
            oracle_type: OracleType::Cursor,
            buffer_size: 0,
        }
    }

    /// Create an OUT parameter for a collection (VARRAY, Nested Table)
    ///
    /// The DbObjectType provides element type information for proper decoding.
    pub fn output_collection(obj_type: &crate::dbobject::DbObjectType) -> Self {
        use crate::dbobject::DbObject;
        // Create a placeholder collection with the type info
        let mut placeholder = DbObject::collection(&obj_type.full_name());
        placeholder.set("_type_schema", Value::String(obj_type.schema.clone()));
        placeholder.set("_type_name", Value::String(obj_type.name.clone()));
        if let Some(elem_type) = obj_type.element_type {
            placeholder.set("_element_type", Value::Integer(elem_type as i64));
        }
        // Store the type OID for bind metadata
        if let Some(ref oid) = obj_type.oid {
            placeholder.set("_type_oid", Value::Bytes(oid.clone()));
        }
        Self {
            value: Some(Value::Collection(placeholder)),
            direction: BindDirection::Output,
            oracle_type: OracleType::Object,
            buffer_size: 0,
        }
    }

    /// Create an IN parameter for a collection (VARRAY, Nested Table)
    ///
    /// The DbObjectType provides element type information for proper encoding,
    /// and the DbObject contains the actual element values.
    ///
    /// # Example
    /// ```ignore
    /// let varray_type = conn.get_type("NUMBER_VARRAY").await?;
    /// let mut coll = DbObject::collection("NUMBER_VARRAY");
    /// coll.append(Value::Integer(1));
    /// coll.append(Value::Integer(2));
    /// let param = BindParam::input_collection(&varray_type, coll);
    /// ```
    pub fn input_collection(
        obj_type: &crate::dbobject::DbObjectType,
        collection: crate::dbobject::DbObject,
    ) -> Self {
        use crate::constants::collection_type;
        use crate::dbobject::{CollectionType, DbObject};
        // Create a collection with both elements and type info
        let mut coll = DbObject::collection(&obj_type.full_name());
        // Copy elements
        coll.elements = collection.elements;
        // Add type metadata
        coll.set("_type_schema", Value::String(obj_type.schema.clone()));
        coll.set("_type_name", Value::String(obj_type.name.clone()));
        if let Some(elem_type) = obj_type.element_type {
            coll.set("_element_type", Value::Integer(elem_type as i64));
        }
        // Store collection type as wire constant (1=index-by, 2=nested, 3=varray)
        if let Some(coll_type) = obj_type.collection_type {
            let wire_code = match coll_type {
                CollectionType::PlsqlIndexTable => collection_type::PLSQL_INDEX_TABLE,
                CollectionType::NestedTable => collection_type::NESTED_TABLE,
                CollectionType::Varray => collection_type::VARRAY,
            };
            coll.set("_collection_type", Value::Integer(wire_code as i64));
        }
        // Store the type OID for TOID construction
        if let Some(ref oid) = obj_type.oid {
            coll.set("_type_oid", Value::Bytes(oid.clone()));
        }
        Self {
            value: Some(Value::Collection(coll)),
            direction: BindDirection::Input,
            oracle_type: OracleType::Object,
            buffer_size: 0,
        }
    }

    /// Create an IN OUT (input/output) parameter
    pub fn input_output(value: Value, buffer_size: u32) -> Self {
        let oracle_type = Self::infer_oracle_type(&value);
        Self {
            value: Some(value),
            direction: BindDirection::InputOutput,
            oracle_type,
            buffer_size,
        }
    }

    /// Create a placeholder value for OUT parameters based on the Oracle type
    /// This is used when sending bind metadata to the server
    pub fn placeholder_value(&self) -> Value {
        if let Some(ref v) = self.value {
            return v.clone();
        }

        // Create an appropriate placeholder based on the oracle type
        match self.oracle_type {
            OracleType::Varchar | OracleType::Char | OracleType::Long => {
                Value::String(String::new())
            }
            OracleType::Number | OracleType::BinaryInteger => Value::Integer(0),
            OracleType::BinaryDouble | OracleType::BinaryFloat => Value::Float(0.0),
            OracleType::Date => Value::Null,
            OracleType::Timestamp | OracleType::TimestampTz | OracleType::TimestampLtz => {
                Value::Null
            }
            OracleType::Raw | OracleType::LongRaw => Value::Bytes(Vec::new()),
            OracleType::Clob | OracleType::Blob => Value::Null,
            OracleType::Cursor => Value::Cursor(RefCursor::new(0, vec![])),
            OracleType::Boolean => Value::Boolean(false),
            _ => Value::Null,
        }
    }

    /// Infer the Oracle type from a Value
    fn infer_oracle_type(value: &Value) -> OracleType {
        match value {
            Value::Null => OracleType::Varchar, // Default to VARCHAR for NULL
            Value::String(_) => OracleType::Varchar,
            Value::Bytes(_) => OracleType::Raw,
            Value::Integer(_) => OracleType::Number,
            Value::Float(_) => OracleType::BinaryDouble,
            Value::Number(_) => OracleType::Number,
            Value::Date(_) => OracleType::Date,
            Value::Timestamp(_) => OracleType::Timestamp,
            Value::RowId(_) => OracleType::Rowid,
            Value::Boolean(_) => OracleType::Boolean,
            Value::Lob(_) => OracleType::Clob, // Default to CLOB
            Value::Json(_) => OracleType::Json,
            Value::Vector(_) => OracleType::Vector,
            Value::Cursor(_) => OracleType::Cursor,
            Value::Collection(_) => OracleType::Object,
        }
    }
}

impl From<Value> for BindParam {
    fn from(value: Value) -> Self {
        BindParam::input(value)
    }
}

impl From<i32> for BindParam {
    fn from(v: i32) -> Self {
        BindParam::input(Value::Integer(v as i64))
    }
}

impl From<i64> for BindParam {
    fn from(v: i64) -> Self {
        BindParam::input(Value::Integer(v))
    }
}

impl From<f64> for BindParam {
    fn from(v: f64) -> Self {
        BindParam::input(Value::Float(v))
    }
}

impl From<&str> for BindParam {
    fn from(v: &str) -> Self {
        BindParam::input(Value::String(v.to_string()))
    }
}

impl From<String> for BindParam {
    fn from(v: String) -> Self {
        BindParam::input(Value::String(v))
    }
}

impl From<bool> for BindParam {
    fn from(v: bool) -> Self {
        BindParam::input(Value::Boolean(v))
    }
}

/// Metadata for a column in a result set
#[derive(Debug, Clone)]
pub struct ColumnInfo {
    /// Column name
    pub name: String,
    /// Oracle data type
    pub oracle_type: OracleType,
    /// Data type size
    pub data_size: u32,
    /// Buffer size for fetching
    pub buffer_size: u32,
    /// Precision (for NUMBER)
    pub precision: i16,
    /// Scale (for NUMBER)
    pub scale: i16,
    /// Whether NULL values are allowed
    pub nullable: bool,
    /// Character set form
    pub csfrm: u8,
    /// Schema name (for object types)
    pub type_schema: Option<String>,
    /// Type name (for object types)
    pub type_name: Option<String>,
    /// Domain schema (23ai+)
    pub domain_schema: Option<String>,
    /// Domain name (23ai+)
    pub domain_name: Option<String>,
    /// Is JSON column
    pub is_json: bool,
    /// Is OSON format
    pub is_oson: bool,
    /// Vector dimensions (23ai+)
    pub vector_dimensions: Option<u32>,
    /// Vector format (23ai+)
    pub vector_format: Option<u8>,
    /// Element type for collections (VARRAY, Nested Table)
    pub element_type: Option<OracleType>,
}

impl ColumnInfo {
    /// Create a new column with minimal info
    pub fn new(name: impl Into<String>, oracle_type: OracleType) -> Self {
        Self {
            name: name.into(),
            oracle_type,
            data_size: 0,
            buffer_size: 0,
            precision: 0,
            scale: 0,
            nullable: true,
            csfrm: 0,
            type_schema: None,
            type_name: None,
            domain_schema: None,
            domain_name: None,
            is_json: false,
            is_oson: false,
            vector_dimensions: None,
            vector_format: None,
            element_type: None,
        }
    }

    /// Check if this column is a LOB type (CLOB, BLOB, BFILE, JSON, or VECTOR)
    pub fn is_lob(&self) -> bool {
        self.oracle_type.is_lob()
    }

    /// Check if this column requires no prefetch (LOB types)
    pub fn requires_no_prefetch(&self) -> bool {
        self.oracle_type.requires_no_prefetch()
    }
}

/// A parsed SQL statement ready for execution
#[derive(Debug, Clone)]
pub struct Statement {
    /// The original SQL text
    sql: String,
    /// SQL as bytes (for sending to server)
    sql_bytes: Vec<u8>,
    /// Statement type
    statement_type: StatementType,
    /// Cursor ID assigned by server (0 = not yet assigned)
    cursor_id: u16,
    /// List of bind parameters in order of appearance
    bind_info_list: Vec<BindInfo>,
    /// Column metadata for queries
    columns: Vec<ColumnInfo>,
    /// Whether the statement has been executed
    executed: bool,
    /// Whether bind metadata has changed
    binds_changed: bool,
    /// Whether column defines are required
    requires_define: bool,
    /// Whether prefetch should be disabled (for LOBs)
    no_prefetch: bool,
    /// Whether this is a DML RETURNING statement
    is_returning: bool,
}

impl Statement {
    /// Create a new statement from SQL text
    pub fn new(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        let sql_bytes = sql.as_bytes().to_vec();

        let mut stmt = Self {
            sql,
            sql_bytes,
            statement_type: StatementType::Unknown,
            cursor_id: 0,
            bind_info_list: Vec::new(),
            columns: Vec::new(),
            executed: false,
            binds_changed: false,
            requires_define: false,
            no_prefetch: false,
            is_returning: false,
        };

        stmt.parse();
        stmt
    }

    /// Get the SQL text
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Get the SQL bytes
    pub fn sql_bytes(&self) -> &[u8] {
        &self.sql_bytes
    }

    /// Get the statement type
    pub fn statement_type(&self) -> StatementType {
        self.statement_type
    }

    /// Check if this is a query (SELECT)
    pub fn is_query(&self) -> bool {
        self.statement_type == StatementType::Query
    }

    /// Check if this is a DML statement
    pub fn is_dml(&self) -> bool {
        self.statement_type == StatementType::Dml
    }

    /// Check if this is a DDL statement
    pub fn is_ddl(&self) -> bool {
        self.statement_type == StatementType::Ddl
    }

    /// Check if this is a PL/SQL block
    pub fn is_plsql(&self) -> bool {
        self.statement_type == StatementType::PlSql
    }

    /// Check if this is a RETURNING statement
    pub fn is_returning(&self) -> bool {
        self.is_returning
    }

    /// Get the cursor ID
    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Set the cursor ID
    pub fn set_cursor_id(&mut self, id: u16) {
        self.cursor_id = id;
    }

    /// Get the bind parameters
    pub fn bind_info(&self) -> &[BindInfo] {
        &self.bind_info_list
    }

    /// Get the column metadata
    pub fn columns(&self) -> &[ColumnInfo] {
        &self.columns
    }

    /// Set column metadata (from server describe)
    pub fn set_columns(&mut self, columns: Vec<ColumnInfo>) {
        self.columns = columns;
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Check if the statement has been executed
    pub fn executed(&self) -> bool {
        self.executed
    }

    /// Mark the statement as executed
    pub fn set_executed(&mut self, executed: bool) {
        self.executed = executed;
    }

    /// Check if binds have changed
    pub fn binds_changed(&self) -> bool {
        self.binds_changed
    }

    /// Set binds changed flag
    pub fn set_binds_changed(&mut self, changed: bool) {
        self.binds_changed = changed;
    }

    /// Check if column define is required
    pub fn requires_define(&self) -> bool {
        self.requires_define
    }

    /// Set requires define flag
    pub fn set_requires_define(&mut self, required: bool) {
        self.requires_define = required;
    }

    /// Check if prefetch should be disabled
    pub fn no_prefetch(&self) -> bool {
        self.no_prefetch
    }

    /// Set no prefetch flag
    pub fn set_no_prefetch(&mut self, no_prefetch: bool) {
        self.no_prefetch = no_prefetch;
    }

    /// Set the statement type (useful for scroll operations that reuse cursors)
    pub fn set_statement_type(&mut self, stmt_type: StatementType) {
        self.statement_type = stmt_type;
    }

    /// Parse the SQL to determine statement type and extract bind names
    fn parse(&mut self) {
        let sql_upper = self.sql.to_uppercase();
        let trimmed = sql_upper.trim_start();

        // Determine statement type from first keyword
        if let Some(first_word) = trimmed.split_whitespace().next() {
            self.statement_type = match first_word {
                "SELECT" | "WITH" => StatementType::Query,
                "INSERT" | "UPDATE" | "DELETE" | "MERGE" => StatementType::Dml,
                "CREATE" | "ALTER" | "DROP" | "GRANT" | "REVOKE" | "ANALYZE" | "AUDIT"
                | "COMMENT" | "TRUNCATE" => StatementType::Ddl,
                "DECLARE" | "BEGIN" | "CALL" => StatementType::PlSql,
                _ => StatementType::Unknown,
            };
        }

        // Don't parse binds for DDL
        if self.statement_type == StatementType::Ddl {
            return;
        }

        // Parse bind variables and check for RETURNING INTO
        self.parse_bind_variables();
    }

    /// Parse bind variables from SQL text
    fn parse_bind_variables(&mut self) {
        let sql = &self.sql;
        let sql_upper = sql.to_uppercase();
        let chars: Vec<char> = sql.chars().collect();
        let chars_upper: Vec<char> = sql_upper.chars().collect();
        let len = chars.len();

        let mut i = 0;
        let mut in_string = false;
        let mut in_comment = false;
        let mut in_line_comment = false;
        let mut returning_found = false;
        let mut into_found = false;

        while i < len {
            let ch = chars[i];

            // Handle string literals
            if ch == '\'' && !in_comment && !in_line_comment {
                in_string = !in_string;
                i += 1;
                continue;
            }

            if in_string {
                i += 1;
                continue;
            }

            // Handle line comments (--)
            if ch == '-' && i + 1 < len && chars[i + 1] == '-' {
                in_line_comment = true;
                i += 2;
                continue;
            }

            if in_line_comment {
                if ch == '\n' {
                    in_line_comment = false;
                }
                i += 1;
                continue;
            }

            // Handle block comments (/* */)
            if ch == '/' && i + 1 < len && chars[i + 1] == '*' {
                in_comment = true;
                i += 2;
                continue;
            }

            if in_comment {
                if ch == '*' && i + 1 < len && chars[i + 1] == '/' {
                    in_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }

            // Check for RETURNING keyword (for DML)
            if self.statement_type == StatementType::Dml && !returning_found {
                if self.match_keyword(&chars_upper, i, "RETURNING") {
                    returning_found = true;
                    i += 9;
                    continue;
                }
            }

            // Check for INTO keyword (after RETURNING)
            if returning_found && !into_found {
                if self.match_keyword(&chars_upper, i, "INTO") {
                    into_found = true;
                    self.is_returning = true;
                    i += 4;
                    continue;
                }
            }

            // Parse bind variable
            if ch == ':' && i + 1 < len {
                let bind_name = self.extract_bind_name(&chars, i + 1);
                if !bind_name.is_empty() {
                    // Check if bind already exists for PL/SQL (allow duplicates otherwise)
                    let should_add = if self.statement_type == StatementType::PlSql {
                        !self.bind_info_list.iter().any(|b| b.name == bind_name)
                    } else {
                        true
                    };

                    if should_add {
                        self.bind_info_list
                            .push(BindInfo::new(bind_name.clone(), into_found));
                    }
                    i += 1 + bind_name.len();
                    continue;
                }
            }

            i += 1;
        }
        // Note: bind_info_list is in order of appearance in SQL, not numerical order.
        // Oracle expects params in this order, so we don't sort.
    }

    /// Check if keyword matches at position
    fn match_keyword(&self, chars: &[char], pos: usize, keyword: &str) -> bool {
        let keyword_chars: Vec<char> = keyword.chars().collect();
        let len = chars.len();

        // Check bounds
        if pos + keyword.len() > len {
            return false;
        }

        // Check preceding character is not alphanumeric
        if pos > 0 && chars[pos - 1].is_alphanumeric() {
            return false;
        }

        // Check keyword matches
        for (i, kc) in keyword_chars.iter().enumerate() {
            if chars[pos + i] != *kc {
                return false;
            }
        }

        // Check following character is not alphanumeric
        let end_pos = pos + keyword.len();
        if end_pos < len && chars[end_pos].is_alphanumeric() {
            return false;
        }

        true
    }

    /// Extract bind variable name starting at position
    fn extract_bind_name(&self, chars: &[char], start: usize) -> String {
        let len = chars.len();

        // Skip leading whitespace
        let mut i = start;
        while i < len && chars[i].is_whitespace() {
            i += 1;
        }

        if i >= len {
            return String::new();
        }

        let first_char = chars[i];

        // Quoted bind name
        if first_char == '"' {
            i += 1;
            let name_start = i;
            while i < len && chars[i] != '"' {
                i += 1;
            }
            if i > name_start {
                return chars[name_start..i].iter().collect();
            }
            return String::new();
        }

        // Numeric bind (positional)
        if first_char.is_ascii_digit() {
            let name_start = i;
            while i < len && chars[i].is_ascii_digit() {
                i += 1;
            }
            return chars[name_start..i].iter().collect();
        }

        // Regular bind name (must start with letter)
        if !first_char.is_alphabetic() {
            return String::new();
        }

        let name_start = i;
        while i < len {
            let ch = chars[i];
            if ch.is_alphanumeric() || ch == '_' || ch == '$' || ch == '#' {
                i += 1;
            } else {
                break;
            }
        }

        // Convert to uppercase for non-quoted names
        chars[name_start..i]
            .iter()
            .collect::<String>()
            .to_uppercase()
    }

    /// Clear statement state for re-execution
    pub fn clear(&mut self) {
        self.cursor_id = 0;
        self.columns.clear();
        self.executed = false;
        self.binds_changed = false;
        self.requires_define = false;
        self.no_prefetch = false;
    }

    /// Clone statement for cache reuse, preserving cursor_id and metadata
    ///
    /// This creates a copy of the statement that can be executed with new
    /// bind values. The cursor_id is preserved if non-zero, allowing Oracle
    /// to skip parsing and reexecute the existing cursor.
    ///
    /// Following python-oracledb's design:
    /// - If cursor_id > 0, the cursor is still valid and can be reexecuted
    /// - If cursor_id = 0, Oracle will issue a fresh cursor
    ///
    /// The `mark_cursor_closed` method in StatementCache resets cursor_id to 0
    /// when a cursor is no longer valid (query complete, DML executed, etc.)
    pub fn clone_for_reuse(&self) -> Self {
        Self {
            sql: self.sql.clone(),
            sql_bytes: self.sql_bytes.clone(),
            statement_type: self.statement_type,
            cursor_id: self.cursor_id,
            bind_info_list: self.bind_info_list.clone(),
            columns: self.columns.clone(),
            executed: self.executed,
            binds_changed: false, // Reset for new execution
            requires_define: false,
            no_prefetch: self.no_prefetch,
            is_returning: self.is_returning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_type_detection() {
        assert_eq!(
            Statement::new("SELECT * FROM dual").statement_type(),
            StatementType::Query
        );
        assert_eq!(
            Statement::new("INSERT INTO t VALUES (1)").statement_type(),
            StatementType::Dml
        );
        assert_eq!(
            Statement::new("UPDATE t SET x = 1").statement_type(),
            StatementType::Dml
        );
        assert_eq!(
            Statement::new("DELETE FROM t").statement_type(),
            StatementType::Dml
        );
        assert_eq!(
            Statement::new("CREATE TABLE t (x NUMBER)").statement_type(),
            StatementType::Ddl
        );
        assert_eq!(
            Statement::new("BEGIN NULL; END;").statement_type(),
            StatementType::PlSql
        );
        assert_eq!(
            Statement::new("DECLARE x NUMBER; BEGIN NULL; END;").statement_type(),
            StatementType::PlSql
        );
    }

    #[test]
    fn test_bind_variable_extraction() {
        let stmt = Statement::new("SELECT * FROM t WHERE x = :x AND y = :y");
        assert_eq!(stmt.bind_info().len(), 2);
        assert_eq!(stmt.bind_info()[0].name, "X");
        assert_eq!(stmt.bind_info()[1].name, "Y");
    }

    #[test]
    fn test_numeric_bind_variables() {
        let stmt = Statement::new("SELECT * FROM t WHERE x = :1 AND y = :2");
        assert_eq!(stmt.bind_info().len(), 2);
        assert_eq!(stmt.bind_info()[0].name, "1");
        assert_eq!(stmt.bind_info()[1].name, "2");
    }

    #[test]
    fn test_duplicate_binds_plsql() {
        // PL/SQL should deduplicate bind names
        let stmt = Statement::new("BEGIN :x := :x + 1; END;");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "X");
    }

    #[test]
    fn test_duplicate_binds_sql() {
        // SQL allows duplicate bind positions
        let stmt = Statement::new("SELECT * FROM t WHERE x = :x OR y = :x");
        assert_eq!(stmt.bind_info().len(), 2);
    }

    #[test]
    fn test_returning_into() {
        let stmt = Statement::new("INSERT INTO t (x) VALUES (:val) RETURNING id INTO :id");
        assert!(stmt.is_returning());
        assert_eq!(stmt.bind_info().len(), 2);
        assert!(!stmt.bind_info()[0].is_return_bind); // :val
        assert!(stmt.bind_info()[1].is_return_bind); // :id
    }

    #[test]
    fn test_binds_in_comments_ignored() {
        let stmt = Statement::new("SELECT * FROM t WHERE x = :x -- AND y = :y");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "X");
    }

    #[test]
    fn test_binds_in_strings_ignored() {
        let stmt = Statement::new("SELECT * FROM t WHERE x = ':not_a_bind' AND y = :y");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "Y");
    }

    #[test]
    fn test_with_query() {
        let stmt = Statement::new("WITH cte AS (SELECT 1 x FROM dual) SELECT * FROM cte");
        assert!(stmt.is_query());
    }

    #[test]
    fn test_quoted_bind_name() {
        let stmt = Statement::new("SELECT * FROM t WHERE x = :\"MyBind\"");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "MyBind");
    }

    #[test]
    fn test_case_insensitive_keywords() {
        assert!(Statement::new("select * from dual").is_query());
        assert!(Statement::new("Select * From dual").is_query());
        assert!(Statement::new("INSERT into t values (1)").is_dml());
    }
}
