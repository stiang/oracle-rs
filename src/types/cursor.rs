//! REF CURSOR support for Oracle PL/SQL
//!
//! This module provides types for working with REF CURSOR (SYS_REFCURSOR)
//! values returned from PL/SQL procedures and functions.

use crate::statement::ColumnInfo;

/// A REF CURSOR value returned from Oracle PL/SQL
///
/// REF CURSORs are cursors that are returned from PL/SQL procedures or functions.
/// They contain a cursor ID and column metadata that can be used to fetch rows.
///
/// # Example
///
/// ```ignore
/// // PL/SQL that returns a REF CURSOR
/// let result = conn.execute(
///     "BEGIN OPEN :1 FOR SELECT id, name FROM employees; END;",
///     &[/* cursor OUT param */]
/// ).await?;
///
/// // Get the cursor from the OUT parameter
/// if let Value::Cursor(ref_cursor) = &result.out_values[0] {
///     // Fetch rows from the cursor
///     let rows = conn.fetch_cursor(ref_cursor).await?;
///     for row in &rows.rows {
///         println!("{:?}", row);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RefCursor {
    /// The server-side cursor ID
    pub(crate) cursor_id: u16,
    /// Column metadata for the cursor's result set
    pub(crate) columns: Vec<ColumnInfo>,
    /// Whether this cursor has been fetched
    pub(crate) fetched: bool,
}

impl RefCursor {
    /// Create a new REF CURSOR with the given cursor ID and columns
    pub(crate) fn new(cursor_id: u16, columns: Vec<ColumnInfo>) -> Self {
        Self {
            cursor_id,
            columns,
            fetched: false,
        }
    }

    /// Get the cursor ID
    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Get the column metadata
    pub fn columns(&self) -> &[ColumnInfo] {
        &self.columns
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Check if the cursor has been fetched
    pub fn is_fetched(&self) -> bool {
        self.fetched
    }

    /// Mark the cursor as fetched (internal use)
    pub(crate) fn mark_fetched(&mut self) {
        self.fetched = true;
    }
}
