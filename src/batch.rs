//! Batch execution support for Oracle connections
//!
//! This module provides types and methods for executing statements multiple times
//! with different bind values efficiently (executemany pattern).
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, BatchBuilder};
//!
//! let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "pass").await?;
//!
//! // Create a batch for inserting multiple rows
//! let batch = BatchBuilder::new("INSERT INTO users (id, name) VALUES (:1, :2)")
//!     .add_row(vec![Value::Integer(1), Value::String("Alice".to_string())])
//!     .add_row(vec![Value::Integer(2), Value::String("Bob".to_string())])
//!     .add_row(vec![Value::Integer(3), Value::String("Charlie".to_string())])
//!     .build();
//!
//! let result = conn.execute_batch(&batch).await?;
//! println!("Rows affected per statement: {:?}", result.row_counts);
//! ```

use crate::error::{Error, Result};
use crate::row::Value;
use crate::statement::Statement;

/// Options for batch execution
#[derive(Debug, Clone, Default)]
pub struct BatchOptions {
    /// Whether to continue execution after errors (batch errors mode)
    pub batch_errors: bool,
    /// Whether to return row counts for each statement
    pub array_dml_row_counts: bool,
    /// Whether to commit after successful completion
    pub auto_commit: bool,
}

impl BatchOptions {
    /// Create default batch options
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable batch errors mode (continue on errors)
    pub fn with_batch_errors(mut self) -> Self {
        self.batch_errors = true;
        self
    }

    /// Enable array DML row counts
    pub fn with_row_counts(mut self) -> Self {
        self.array_dml_row_counts = true;
        self
    }

    /// Enable auto-commit
    pub fn with_auto_commit(mut self) -> Self {
        self.auto_commit = true;
        self
    }
}

/// A collection of bind values for batch execution
#[derive(Debug, Clone)]
pub struct BatchBinds {
    /// The SQL statement
    pub(crate) sql: String,
    /// Parsed statement information
    pub(crate) statement: Statement,
    /// Rows of bind values (each row is one execution)
    pub(crate) rows: Vec<Vec<Value>>,
    /// Number of columns per row
    pub(crate) num_columns: usize,
    /// Execution options
    pub(crate) options: BatchOptions,
}

impl BatchBinds {
    /// Create a new batch with the given SQL statement
    pub fn new(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        let statement = Statement::new(&sql);
        Self {
            sql,
            statement,
            rows: Vec::new(),
            num_columns: 0,
            options: BatchOptions::default(),
        }
    }

    /// Add a row of bind values
    pub fn add_row(&mut self, values: Vec<Value>) -> &mut Self {
        if self.rows.is_empty() {
            self.num_columns = values.len();
        }
        self.rows.push(values);
        self
    }

    /// Set batch execution options
    pub fn with_options(&mut self, options: BatchOptions) -> &mut Self {
        self.options = options;
        self
    }

    /// Get the number of rows (executions)
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of bind columns per row
    pub fn column_count(&self) -> usize {
        self.num_columns
    }

    /// Get the SQL statement
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Validate that all rows have the same number of columns
    pub fn validate(&self) -> Result<()> {
        if self.rows.is_empty() {
            return Err(Error::Internal("Batch has no rows".to_string()));
        }

        for (i, row) in self.rows.iter().enumerate() {
            if row.len() != self.num_columns {
                return Err(Error::Internal(format!(
                    "Row {} has {} columns, expected {}",
                    i,
                    row.len(),
                    self.num_columns
                )));
            }
        }

        Ok(())
    }
}

/// Builder for creating batch execution requests
#[derive(Debug)]
pub struct BatchBuilder {
    batch: BatchBinds,
}

impl BatchBuilder {
    /// Create a new batch builder with the given SQL statement
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            batch: BatchBinds::new(sql),
        }
    }

    /// Add a row of bind values
    pub fn add_row(mut self, values: Vec<Value>) -> Self {
        self.batch.add_row(values);
        self
    }

    /// Add multiple rows at once
    pub fn add_rows(mut self, rows: Vec<Vec<Value>>) -> Self {
        for row in rows {
            self.batch.add_row(row);
        }
        self
    }

    /// Enable batch errors mode
    pub fn with_batch_errors(mut self) -> Self {
        self.batch.options.batch_errors = true;
        self
    }

    /// Enable array DML row counts
    pub fn with_row_counts(mut self) -> Self {
        self.batch.options.array_dml_row_counts = true;
        self
    }

    /// Enable auto-commit
    pub fn with_auto_commit(mut self) -> Self {
        self.batch.options.auto_commit = true;
        self
    }

    /// Build the batch
    pub fn build(self) -> BatchBinds {
        self.batch
    }
}

/// Result of batch execution
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Number of rows affected for each statement (if requested)
    pub row_counts: Option<Vec<u64>>,
    /// Total rows affected
    pub total_rows_affected: u64,
    /// Errors encountered (if batch_errors mode enabled)
    pub errors: Vec<BatchError>,
    /// Number of successful executions
    pub success_count: usize,
    /// Number of failed executions
    pub failure_count: usize,
}

impl BatchResult {
    /// Create a new empty batch result
    pub fn new() -> Self {
        Self {
            row_counts: None,
            total_rows_affected: 0,
            errors: Vec::new(),
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Create a batch result with row counts
    pub fn with_row_counts(counts: Vec<u64>) -> Self {
        let total: u64 = counts.iter().sum();
        let success_count = counts.len();
        Self {
            row_counts: Some(counts),
            total_rows_affected: total,
            errors: Vec::new(),
            success_count,
            failure_count: 0,
        }
    }

    /// Check if all executions succeeded
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if there were any errors
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// An error that occurred during batch execution
#[derive(Debug, Clone)]
pub struct BatchError {
    /// The row index where the error occurred (0-based)
    pub row_index: usize,
    /// Oracle error code
    pub code: u32,
    /// Error message
    pub message: String,
}

impl BatchError {
    /// Create a new batch error
    pub fn new(row_index: usize, code: u32, message: impl Into<String>) -> Self {
        Self {
            row_index,
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Row {}: ORA-{:05}: {}",
            self.row_index, self.code, self.message
        )
    }
}

impl std::error::Error for BatchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_builder() {
        let batch = BatchBuilder::new("INSERT INTO t (a, b) VALUES (:1, :2)")
            .add_row(vec![Value::Integer(1), Value::String("a".to_string())])
            .add_row(vec![Value::Integer(2), Value::String("b".to_string())])
            .build();

        assert_eq!(batch.row_count(), 2);
        assert_eq!(batch.column_count(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_validation() {
        let mut batch = BatchBinds::new("INSERT INTO t (a) VALUES (:1)");
        batch.add_row(vec![Value::Integer(1)]);
        batch.add_row(vec![Value::Integer(2)]);

        assert!(batch.validate().is_ok());
    }

    #[test]
    fn test_batch_validation_empty() {
        let batch = BatchBinds::new("INSERT INTO t (a) VALUES (:1)");
        assert!(batch.validate().is_err());
    }

    #[test]
    fn test_batch_options() {
        let opts = BatchOptions::new()
            .with_batch_errors()
            .with_row_counts()
            .with_auto_commit();

        assert!(opts.batch_errors);
        assert!(opts.array_dml_row_counts);
        assert!(opts.auto_commit);
    }

    #[test]
    fn test_batch_result() {
        let result = BatchResult::with_row_counts(vec![1, 2, 3]);

        assert_eq!(result.total_rows_affected, 6);
        assert_eq!(result.success_count, 3);
        assert!(result.is_success());
        assert!(!result.has_errors());
    }

    #[test]
    fn test_batch_error_display() {
        let err = BatchError::new(5, 1, "test error");
        assert_eq!(err.to_string(), "Row 5: ORA-00001: test error");
    }

    #[test]
    fn test_add_multiple_rows() {
        let batch = BatchBuilder::new("INSERT INTO t (a) VALUES (:1)")
            .add_rows(vec![
                vec![Value::Integer(1)],
                vec![Value::Integer(2)],
                vec![Value::Integer(3)],
            ])
            .build();

        assert_eq!(batch.row_count(), 3);
    }
}
