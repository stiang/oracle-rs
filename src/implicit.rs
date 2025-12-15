//! Implicit results support for Oracle PL/SQL procedures
//!
//! Oracle 12.1+ supports returning multiple result sets from PL/SQL procedures
//! using `dbms_sql.return_result()`. This module provides types to handle these
//! implicit result sets.
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::Connection;
//!
//! let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "pass").await?;
//!
//! // Execute PL/SQL that returns implicit results
//! let result = conn.execute_plsql(r#"
//!     declare
//!         c1 sys_refcursor;
//!         c2 sys_refcursor;
//!     begin
//!         open c1 for select * from employees;
//!         dbms_sql.return_result(c1);
//!
//!         open c2 for select * from departments;
//!         dbms_sql.return_result(c2);
//!     end;
//! "#).await?;
//!
//! // Iterate over implicit result sets
//! for (i, resultset) in result.implicit_results.iter().enumerate() {
//!     println!("Result set #{}", i + 1);
//!     for row in &resultset.rows {
//!         println!("{:?}", row);
//!     }
//! }
//! ```

use crate::row::Row;
use crate::statement::ColumnInfo;

/// An implicit result set returned from a PL/SQL procedure
#[derive(Debug, Clone)]
pub struct ImplicitResult {
    /// Cursor ID for this result set
    pub cursor_id: u16,
    /// Column metadata
    pub columns: Vec<ColumnInfo>,
    /// Rows from this result set
    pub rows: Vec<Row>,
    /// Whether there are more rows to fetch
    pub has_more_rows: bool,
}

impl ImplicitResult {
    /// Create a new implicit result
    pub fn new(cursor_id: u16, columns: Vec<ColumnInfo>, rows: Vec<Row>) -> Self {
        Self {
            cursor_id,
            columns,
            rows,
            has_more_rows: false,
        }
    }

    /// Create an empty implicit result
    pub fn empty() -> Self {
        Self {
            cursor_id: 0,
            columns: Vec::new(),
            rows: Vec::new(),
            has_more_rows: false,
        }
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Check if this result set is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a column by name
    pub fn column(&self, name: &str) -> Option<&ColumnInfo> {
        self.columns.iter().find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Get an iterator over the rows
    pub fn iter(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter()
    }
}

impl IntoIterator for ImplicitResult {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// Collection of implicit results from a PL/SQL execution
#[derive(Debug, Clone, Default)]
pub struct ImplicitResults {
    /// The implicit result sets
    pub results: Vec<ImplicitResult>,
}

impl ImplicitResults {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self { results: Vec::new() }
    }

    /// Add an implicit result set
    pub fn add(&mut self, result: ImplicitResult) {
        self.results.push(result);
    }

    /// Get the number of result sets
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if there are no result sets
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Get a result set by index
    pub fn get(&self, index: usize) -> Option<&ImplicitResult> {
        self.results.get(index)
    }

    /// Get an iterator over the result sets
    pub fn iter(&self) -> impl Iterator<Item = &ImplicitResult> {
        self.results.iter()
    }
}

impl IntoIterator for ImplicitResults {
    type Item = ImplicitResult;
    type IntoIter = std::vec::IntoIter<ImplicitResult>;

    fn into_iter(self) -> Self::IntoIter {
        self.results.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::OracleType;
    use crate::row::Value;

    #[test]
    fn test_implicit_result_creation() {
        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ];
        let rows = vec![
            Row::new(vec![Value::Integer(1), Value::String("Alice".to_string())]),
        ];
        let result = ImplicitResult::new(1, columns, rows);

        assert_eq!(result.cursor_id, 1);
        assert_eq!(result.column_count(), 2);
        assert_eq!(result.row_count(), 1);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_implicit_result_empty() {
        let result = ImplicitResult::empty();
        assert_eq!(result.cursor_id, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_implicit_result_column_lookup() {
        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ];
        let result = ImplicitResult::new(1, columns, Vec::new());

        assert!(result.column("ID").is_some());
        assert!(result.column("id").is_some()); // case-insensitive
        assert!(result.column("MISSING").is_none());
    }

    #[test]
    fn test_implicit_results_collection() {
        let mut results = ImplicitResults::new();
        assert!(results.is_empty());

        results.add(ImplicitResult::empty());
        results.add(ImplicitResult::empty());

        assert_eq!(results.len(), 2);
        assert!(!results.is_empty());
        assert!(results.get(0).is_some());
        assert!(results.get(5).is_none());
    }

    #[test]
    fn test_implicit_result_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = ImplicitResult::new(1, Vec::new(), rows);

        let collected: Vec<_> = result.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_implicit_results_iterator() {
        let mut results = ImplicitResults::new();
        results.add(ImplicitResult::new(1, Vec::new(), Vec::new()));
        results.add(ImplicitResult::new(2, Vec::new(), Vec::new()));

        let ids: Vec<_> = results.iter().map(|r| r.cursor_id).collect();
        assert_eq!(ids, vec![1, 2]);
    }
}
