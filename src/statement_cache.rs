//! Statement caching for improved performance
//!
//! This module provides client-side statement caching to avoid repeated
//! parsing of SQL statements on the Oracle server. When a statement is
//! executed, its cursor ID and metadata are cached. Subsequent executions
//! of the same SQL text can reuse the cached cursor, skipping the parse phase.
//!
//! # Cursor Lifecycle
//!
//! Following python-oracledb's design:
//! - Cursors are closed by Oracle when a query completes (has_more_rows=false)
//! - DML/DDL/PL-SQL cursors are closed immediately after execution (no fetch phase)
//! - When a cursor is closed, its cursor_id is reset to 0 in the cached statement
//! - On next execution, cursor_id=0 forces Oracle to issue a fresh cursor
//! - This prevents data corruption from reusing stale cursor IDs

use indexmap::IndexMap;
use std::time::Instant;

use crate::statement::Statement;

/// Wrapper for a cached statement with usage tracking
#[derive(Debug)]
struct CachedStatement {
    /// The cached statement with cursor_id and metadata
    statement: Statement,
    /// Whether the statement is currently in use
    in_use: bool,
    /// When this statement was last used
    last_used: Instant,
}

impl CachedStatement {
    fn new(statement: Statement) -> Self {
        Self {
            statement,
            in_use: false,
            last_used: Instant::now(),
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// Client-side statement cache using LRU eviction
///
/// The cache stores prepared statements keyed by their SQL text.
/// When a statement is retrieved from cache, its cursor ID is preserved,
/// allowing Oracle to skip parsing and use the cached server cursor.
///
/// # Example
///
/// ```ignore
/// // Statement caching is automatic when enabled via config
/// let mut config = Config::new("localhost", 1521, "FREEPDB1", "user", "pass");
/// config.set_stmtcachesize(20);  // Enable with 20 statement cache
///
/// let conn = Connection::connect_with_config(config).await?;
///
/// // First call: parses SQL, gets cursor_id from Oracle
/// conn.query("SELECT * FROM users WHERE id = :1", &[Value::Integer(1)]).await?;
///
/// // Second call: reuses cached cursor, no re-parsing!
/// conn.query("SELECT * FROM users WHERE id = :1", &[Value::Integer(2)]).await?;
/// ```
#[derive(Debug)]
pub struct StatementCache {
    /// The cache using IndexMap for O(1) lookup + LRU ordering
    cache: IndexMap<String, CachedStatement>,
    /// Maximum number of statements to cache
    max_size: usize,
}

impl StatementCache {
    /// Create a new statement cache with the given maximum size
    ///
    /// A size of 0 effectively disables caching.
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: IndexMap::with_capacity(max_size),
            max_size,
        }
    }

    /// Get a statement from the cache, if available
    ///
    /// Returns a clone of the cached statement with preserved cursor_id and metadata.
    /// If the cached statement is already in use, returns a fresh statement.
    /// Updates LRU ordering on hit.
    pub fn get(&mut self, sql: &str) -> Option<Statement> {
        if self.max_size == 0 {
            return None;
        }

        // Check if we have this SQL cached
        if let Some(cached) = self.cache.get_mut(sql) {
            cached.touch();

            if cached.in_use {
                // Statement is in use - return a fresh statement
                // The caller will get a new cursor from Oracle
                tracing::trace!(sql = sql, "Statement cache hit but in use, returning fresh");
                return None;
            }

            // Mark as in use and return a clone for reuse
            // clone_for_reuse preserves cursor_id if non-zero, allowing reexecution
            cached.in_use = true;
            tracing::trace!(
                sql = sql,
                cursor_id = cached.statement.cursor_id(),
                "Statement cache hit"
            );
            return Some(cached.statement.clone_for_reuse());
        }

        tracing::trace!(sql = sql, "Statement cache miss");
        None
    }

    /// Store a statement in the cache
    ///
    /// DDL statements are never cached. If the cache is full, the least
    /// recently used statement is evicted and its cursor ID is queued for closing.
    pub fn put(&mut self, sql: String, statement: Statement) {
        if self.max_size == 0 {
            return;
        }

        // Never cache DDL statements (CREATE, ALTER, DROP, etc.)
        if statement.is_ddl() {
            tracing::trace!(sql = sql, "Not caching DDL statement");
            return;
        }

        // Don't cache statements without a cursor_id (not yet executed)
        if statement.cursor_id() == 0 {
            tracing::trace!(sql = sql, "Not caching statement without cursor_id");
            return;
        }

        // Check if already cached (update it)
        if let Some(cached) = self.cache.get_mut(&sql) {
            cached.statement = statement;
            cached.in_use = false;
            cached.touch();
            tracing::trace!(sql = sql, "Updated existing cache entry");
            return;
        }

        // Evict LRU entry if cache is full
        if self.cache.len() >= self.max_size {
            self.evict_lru();
        }

        tracing::trace!(
            sql = sql,
            cursor_id = statement.cursor_id(),
            "Adding statement to cache"
        );
        self.cache.insert(sql, CachedStatement::new(statement));
    }

    /// Return a statement to the cache after use
    ///
    /// This marks the statement as no longer in use so it can be reused.
    pub fn return_statement(&mut self, sql: &str) {
        if let Some(cached) = self.cache.get_mut(sql) {
            cached.in_use = false;
            tracing::trace!(sql = sql, "Statement returned to cache");
        }
    }

    /// Mark a cursor as closed in the cache
    ///
    /// This should be called when a query completes (has_more_rows=false) or
    /// when DML/DDL/PL-SQL execution completes.
    ///
    /// Following python-oracledb's clear_cursor design, we reset cursor_id to 0
    /// so that the next execution will get a fresh cursor from Oracle.
    /// This prevents data corruption from reusing stale cursor IDs.
    ///
    /// # Parameters
    ///
    /// * `sql` - The SQL statement text
    pub fn mark_cursor_closed(&mut self, sql: &str) {
        if let Some(cached) = self.cache.get_mut(sql) {
            let old_cursor_id = cached.statement.cursor_id();
            if old_cursor_id != 0 {
                // Reset cursor_id to 0 - next execution will get a fresh cursor
                cached.statement.set_cursor_id(0);
                cached.statement.set_executed(false);
                
                tracing::trace!(
                    sql = sql,
                    old_cursor_id = old_cursor_id,
                    "Cursor closed, reset cursor_id to 0"
                );
            }
        }
    }

    /// Clear all cached statements
    ///
    /// This should be called when the session changes (e.g., DRCP session switch).
    pub fn clear(&mut self) {
        self.cache.clear();
        tracing::debug!("Statement cache cleared");
    }

    /// Get the current number of cached statements
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get the maximum cache size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Evict the least recently used entry
    fn evict_lru(&mut self) {
        // Find the LRU entry (first entry that's not in use)
        let lru_key = self
            .cache
            .iter()
            .filter(|(_, cached)| !cached.in_use)
            .min_by_key(|(_, cached)| cached.last_used)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            if let Some(cached) = self.cache.swap_remove(&key) {
                tracing::trace!(
                    sql = key,
                    cursor_id = cached.statement.cursor_id(),
                    "Evicted LRU statement from cache"
                );
            }
        } else {
            // All statements are in use - this is rare but possible
            tracing::warn!("Statement cache full and all statements in use");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    #[test]
    fn test_cache_basic() {
        let mut cache = StatementCache::new(5);

        // Add a statement
        let stmt = make_test_statement("SELECT 1 FROM DUAL", 100);
        cache.put("SELECT 1 FROM DUAL".to_string(), stmt);

        assert_eq!(cache.len(), 1);

        // Retrieve it
        let cached = cache.get("SELECT 1 FROM DUAL").expect("Should be cached");
        assert_eq!(cached.cursor_id(), 100);

        // Return it
        cache.return_statement("SELECT 1 FROM DUAL");
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = StatementCache::new(5);
        assert!(cache.get("SELECT 1 FROM DUAL").is_none());
    }

    #[test]
    fn test_cache_disabled() {
        let mut cache = StatementCache::new(0);

        let stmt = make_test_statement("SELECT 1 FROM DUAL", 100);
        cache.put("SELECT 1 FROM DUAL".to_string(), stmt);

        assert_eq!(cache.len(), 0);
        assert!(cache.get("SELECT 1 FROM DUAL").is_none());
    }

    #[test]
    fn test_ddl_not_cached() {
        let mut cache = StatementCache::new(5);

        let mut stmt = Statement::new("CREATE TABLE test (id NUMBER)");
        stmt.set_cursor_id(100);
        cache.put("CREATE TABLE test (id NUMBER)".to_string(), stmt);

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_no_cursor_not_cached() {
        let mut cache = StatementCache::new(5);

        // Statement without cursor_id should not be cached
        let stmt = Statement::new("SELECT 1 FROM DUAL");
        cache.put("SELECT 1 FROM DUAL".to_string(), stmt);

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = StatementCache::new(3);

        // Add 3 statements
        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 1),
        );
        cache.put(
            "SELECT 2 FROM DUAL".to_string(),
            make_test_statement("SELECT 2 FROM DUAL", 2),
        );
        cache.put(
            "SELECT 3 FROM DUAL".to_string(),
            make_test_statement("SELECT 3 FROM DUAL", 3),
        );

        assert_eq!(cache.len(), 3);

        // Access the first one to make it recently used
        cache.get("SELECT 1 FROM DUAL");
        cache.return_statement("SELECT 1 FROM DUAL");

        // Add a 4th - should evict "SELECT 2" (LRU)
        cache.put(
            "SELECT 4 FROM DUAL".to_string(),
            make_test_statement("SELECT 4 FROM DUAL", 4),
        );

        assert_eq!(cache.len(), 3);
        assert!(cache.get("SELECT 2 FROM DUAL").is_none()); // Evicted
        assert!(cache.get("SELECT 1 FROM DUAL").is_some()); // Still there
    }

    #[test]
    fn test_in_use_not_returned() {
        let mut cache = StatementCache::new(5);

        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 100),
        );

        // Get the statement (marks it in use)
        let _ = cache.get("SELECT 1 FROM DUAL");

        // Try to get it again - should return None because it's in use
        assert!(cache.get("SELECT 1 FROM DUAL").is_none());

        // Return it
        cache.return_statement("SELECT 1 FROM DUAL");

        // Now we can get it again
        assert!(cache.get("SELECT 1 FROM DUAL").is_some());
    }

    #[test]
    fn test_clear() {
        let mut cache = StatementCache::new(5);

        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 1),
        );
        cache.put(
            "SELECT 2 FROM DUAL".to_string(),
            make_test_statement("SELECT 2 FROM DUAL", 2),
        );

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_update_existing() {
        let mut cache = StatementCache::new(5);

        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 100),
        );

        // Update with new cursor_id
        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 200),
        );

        assert_eq!(cache.len(), 1);

        let cached = cache.get("SELECT 1 FROM DUAL").unwrap();
        assert_eq!(cached.cursor_id(), 200);
    }

    #[test]
    fn test_mark_cursor_closed() {
        let mut cache = StatementCache::new(5);

        // Add a statement with cursor_id
        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 100),
        );

        // Get it (marks in use)
        let stmt = cache.get("SELECT 1 FROM DUAL").expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 100);

        // Return and mark cursor as closed
        cache.return_statement("SELECT 1 FROM DUAL");
        cache.mark_cursor_closed("SELECT 1 FROM DUAL");

        // Get it again - should have cursor_id = 0
        let stmt = cache.get("SELECT 1 FROM DUAL").expect("Should still be cached");
        assert_eq!(stmt.cursor_id(), 0); // Reset to 0
        assert!(!stmt.executed()); // Also reset
    }

    #[test]
    fn test_mark_cursor_closed_nonexistent() {
        let mut cache = StatementCache::new(5);

        // Should not panic when marking non-existent statement
        cache.mark_cursor_closed("SELECT 1 FROM DUAL");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_mark_cursor_closed_already_zero() {
        let mut cache = StatementCache::new(5);

        // Add statement, mark closed, then mark closed again
        cache.put(
            "SELECT 1 FROM DUAL".to_string(),
            make_test_statement("SELECT 1 FROM DUAL", 100),
        );
        cache.mark_cursor_closed("SELECT 1 FROM DUAL");
        cache.mark_cursor_closed("SELECT 1 FROM DUAL"); // Should be no-op

        let stmt = cache.get("SELECT 1 FROM DUAL").expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 0);
    }

    #[test]
    fn test_cursor_lifecycle_query_complete() {
        // Simulates: execute query -> fetch all rows -> cursor closed -> reexecute
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM employees";

        // First execution: gets cursor_id 100 from Oracle
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(100);
        stmt.set_executed(true);
        cache.put(sql.to_string(), stmt);

        // Get cached statement for reuse
        let cached = cache.get(sql).expect("Should be cached");
        assert_eq!(cached.cursor_id(), 100);

        // Simulate: query completed (has_more_rows = false)
        // Mark cursor as closed
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Next execution: should get cursor_id = 0
        // This forces Oracle to issue a fresh cursor
        let cached = cache.get(sql).expect("Should still be cached");
        assert_eq!(cached.cursor_id(), 0);
    }

    #[test]
    fn test_cursor_lifecycle_dml() {
        // Simulates: execute DML -> cursor closed immediately
        let mut cache = StatementCache::new(5);
        let sql = "INSERT INTO t VALUES (1)";

        // First execution: gets cursor_id 200 from Oracle
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(200);
        stmt.set_executed(true);
        cache.put(sql.to_string(), stmt);

        // DML cursors are always closed after execution
        cache.mark_cursor_closed(sql);

        // Next execution: should get cursor_id = 0
        let cached = cache.get(sql).expect("Should still be cached");
        assert_eq!(cached.cursor_id(), 0);
    }

    #[test]
    fn test_cursor_lifecycle_error_recovery() {
        // Simulates: execute -> error -> cursor state unknown -> mark closed
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM employees";

        // First execution succeeded
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(100);
        stmt.set_executed(true);
        cache.put(sql.to_string(), stmt);

        // Get for second execution
        let _ = cache.get(sql);

        // Execution failed - mark cursor closed for safety
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Next execution gets fresh cursor
        let cached = cache.get(sql).expect("Should be cached");
        assert_eq!(cached.cursor_id(), 0);
    }
}
