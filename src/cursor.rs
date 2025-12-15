//! Scrollable cursor support for Oracle connections
//!
//! This module provides types for scrollable cursors that allow
//! bidirectional navigation through result sets.
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, ScrollableCursor, FetchOrientation};
//!
//! let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "pass").await?;
//!
//! // Open a scrollable cursor
//! let mut cursor = conn.open_scrollable_cursor(
//!     "SELECT * FROM employees ORDER BY employee_id"
//! ).await?;
//!
//! // Navigate to different positions
//! let first_row = cursor.scroll(FetchOrientation::First, 0).await?;
//! let last_row = cursor.scroll(FetchOrientation::Last, 0).await?;
//! let row_5 = cursor.scroll(FetchOrientation::Absolute, 5).await?;
//!
//! // Close the cursor
//! cursor.close().await?;
//! ```

use crate::constants::FetchOrientation;
use crate::row::Row;
use crate::statement::ColumnInfo;

/// A scrollable cursor for navigating result sets
///
/// Scrollable cursors allow moving forward and backward through result sets,
/// jumping to specific positions, and fetching from various positions.
/// This incurs additional overhead on the server to maintain cursor state.
#[derive(Debug)]
pub struct ScrollableCursor {
    /// Cursor ID on the server
    pub(crate) cursor_id: u16,
    /// Column metadata
    pub(crate) columns: Vec<ColumnInfo>,
    /// Whether the cursor is open
    pub(crate) is_open: bool,
    /// Current row position (1-based, 0 means before first row)
    pub(crate) position: i64,
    /// Total row count (if known)
    pub(crate) row_count: Option<u64>,
}

impl ScrollableCursor {
    /// Create a new scrollable cursor
    pub(crate) fn new(cursor_id: u16, columns: Vec<ColumnInfo>) -> Self {
        Self {
            cursor_id,
            columns,
            is_open: true,
            position: 0,
            row_count: None,
        }
    }

    /// Get the cursor ID
    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Get column metadata
    pub fn columns(&self) -> &[ColumnInfo] {
        &self.columns
    }

    /// Check if the cursor is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Get the current position (1-based)
    pub fn position(&self) -> i64 {
        self.position
    }

    /// Get the total row count if known
    pub fn row_count(&self) -> Option<u64> {
        self.row_count
    }

    /// Mark the cursor as closed
    pub(crate) fn mark_closed(&mut self) {
        self.is_open = false;
    }

    /// Update position after a scroll operation
    pub(crate) fn update_position(&mut self, new_position: i64) {
        self.position = new_position;
    }
}

/// Options for creating scrollable cursors
#[derive(Debug, Clone, Default)]
pub struct ScrollableCursorOptions {
    /// Array size for batch fetching
    pub array_size: u32,
}

impl ScrollableCursorOptions {
    /// Create new scrollable cursor options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the array size
    pub fn with_array_size(mut self, size: u32) -> Self {
        self.array_size = size;
        self
    }
}

/// Result from a scroll operation
#[derive(Debug)]
pub struct ScrollResult {
    /// The rows fetched
    pub rows: Vec<Row>,
    /// New cursor position after scroll
    pub position: i64,
    /// Whether the cursor hit the beginning
    pub at_beginning: bool,
    /// Whether the cursor hit the end
    pub at_end: bool,
}

impl ScrollResult {
    /// Create a new scroll result
    pub fn new(rows: Vec<Row>, position: i64) -> Self {
        Self {
            rows,
            position,
            at_beginning: false,
            at_end: false,
        }
    }

    /// Get the first row if any
    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }

    /// Check if no rows were returned
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get the number of rows returned
    pub fn len(&self) -> usize {
        self.rows.len()
    }
}

/// Scroll mode for Python-compatible API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollMode {
    /// Move to first row
    First,
    /// Move to last row
    Last,
    /// Move relative to current position (default)
    Relative,
    /// Move to absolute position
    Absolute,
}

impl Default for ScrollMode {
    fn default() -> Self {
        Self::Relative
    }
}

impl From<ScrollMode> for FetchOrientation {
    fn from(mode: ScrollMode) -> Self {
        match mode {
            ScrollMode::First => FetchOrientation::First,
            ScrollMode::Last => FetchOrientation::Last,
            ScrollMode::Relative => FetchOrientation::Relative,
            ScrollMode::Absolute => FetchOrientation::Absolute,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::OracleType;

    #[test]
    fn test_scrollable_cursor_creation() {
        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ];
        let cursor = ScrollableCursor::new(123, columns);

        assert_eq!(cursor.cursor_id(), 123);
        assert_eq!(cursor.columns().len(), 2);
        assert!(cursor.is_open());
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn test_scrollable_cursor_close() {
        let mut cursor = ScrollableCursor::new(1, Vec::new());
        assert!(cursor.is_open());
        cursor.mark_closed();
        assert!(!cursor.is_open());
    }

    #[test]
    fn test_scroll_result() {
        let rows = vec![Row::new(vec![crate::row::Value::Integer(1)])];
        let result = ScrollResult::new(rows, 5);

        assert_eq!(result.len(), 1);
        assert!(!result.is_empty());
        assert_eq!(result.position, 5);
        assert!(result.first().is_some());
    }

    #[test]
    fn test_scroll_mode_conversion() {
        assert_eq!(FetchOrientation::from(ScrollMode::First), FetchOrientation::First);
        assert_eq!(FetchOrientation::from(ScrollMode::Last), FetchOrientation::Last);
        assert_eq!(FetchOrientation::from(ScrollMode::Relative), FetchOrientation::Relative);
        assert_eq!(FetchOrientation::from(ScrollMode::Absolute), FetchOrientation::Absolute);
    }

    #[test]
    fn test_scrollable_cursor_options() {
        let opts = ScrollableCursorOptions::new()
            .with_array_size(50);
        assert_eq!(opts.array_size, 50);
    }
}
