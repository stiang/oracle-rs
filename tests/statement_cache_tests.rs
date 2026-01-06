//! Tests for statement caching functionality
//!
//! These tests verify the statement cache behavior, cursor lifecycle tracking,
//! and the prevention of stale cursor ID reuse.

use oracle_rs::statement::{Statement, StatementType};
use oracle_rs::statement_cache::StatementCache;

mod cache_basic_tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    #[test]
    fn test_cache_creation() {
        let cache = StatementCache::new(10);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert_eq!(cache.max_size(), 10);
    }

    #[test]
    fn test_cache_put_and_get() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM dual";

        cache.put(sql.to_string(), make_test_statement(sql, 100));
        assert_eq!(cache.len(), 1);

        let stmt = cache.get(sql).expect("Should retrieve cached statement");
        assert_eq!(stmt.cursor_id(), 100);
        assert!(stmt.executed());
    }

    #[test]
    fn test_cache_preserves_statement_type() {
        let mut cache = StatementCache::new(5);

        // Query
        let sql_query = "SELECT * FROM emp";
        cache.put(sql_query.to_string(), make_test_statement(sql_query, 1));
        let stmt = cache.get(sql_query).unwrap();
        assert_eq!(stmt.statement_type(), StatementType::Query);

        cache.return_statement(sql_query);

        // DML
        let sql_dml = "INSERT INTO t VALUES (1)";
        cache.put(sql_dml.to_string(), make_test_statement(sql_dml, 2));
        let stmt = cache.get(sql_dml).unwrap();
        assert_eq!(stmt.statement_type(), StatementType::Dml);
    }
}

mod cursor_lifecycle_tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    /// Test the full cursor lifecycle for a SELECT query:
    /// 1. First execution gets a cursor from Oracle
    /// 2. Query completes (has_more_rows = false)
    /// 3. Cursor is marked closed, resetting cursor_id to 0
    /// 4. Next execution gets a fresh cursor
    #[test]
    fn test_query_cursor_lifecycle() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM employees WHERE dept_id = :1";

        // Step 1: First execution - Oracle returns cursor_id 100
        cache.put(sql.to_string(), make_test_statement(sql, 100));

        // Step 2: Get cached statement for reuse
        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 100, "Should have original cursor_id");

        // Step 3: Query completes, return and mark closed
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Step 4: Next execution should get cursor_id = 0
        let stmt = cache.get(sql).expect("Should still be cached");
        assert_eq!(stmt.cursor_id(), 0, "cursor_id should be reset to 0");
        assert!(!stmt.executed(), "executed flag should be reset");
    }

    /// Test cursor lifecycle for DML (INSERT/UPDATE/DELETE):
    /// DML cursors are closed immediately after execution (no fetch phase)
    #[test]
    fn test_dml_cursor_lifecycle() {
        let mut cache = StatementCache::new(5);
        let sql = "UPDATE employees SET salary = :1 WHERE id = :2";

        // First execution
        cache.put(sql.to_string(), make_test_statement(sql, 200));

        // DML has no fetch phase - cursor is closed immediately
        cache.mark_cursor_closed(sql);

        // Next execution should get fresh cursor
        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 0);
    }

    /// Test cursor lifecycle for PL/SQL blocks
    #[test]
    fn test_plsql_cursor_lifecycle() {
        let mut cache = StatementCache::new(5);
        let sql = "BEGIN :result := calculate_bonus(:emp_id); END;";

        cache.put(sql.to_string(), make_test_statement(sql, 300));

        // PL/SQL blocks are like DML - closed after execution
        cache.mark_cursor_closed(sql);

        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 0);
        assert_eq!(stmt.statement_type(), StatementType::PlSql);
    }

    /// Test error recovery: when an error occurs, mark cursor as closed
    /// since the server-side state is unknown
    #[test]
    fn test_error_recovery_cursor_lifecycle() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM employees";

        // First execution succeeded
        cache.put(sql.to_string(), make_test_statement(sql, 100));

        // Get for second execution
        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 100);

        // Simulate: execution failed with an Oracle error
        // We should return the statement and mark cursor closed
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Verify cursor_id is reset
        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 0, "Should get fresh cursor after error");
    }
}

mod concurrent_usage_tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    /// Test that a statement in use cannot be retrieved again
    #[test]
    fn test_in_use_blocking() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM dual";

        cache.put(sql.to_string(), make_test_statement(sql, 100));

        // First get - marks as in use
        let stmt1 = cache.get(sql);
        assert!(stmt1.is_some());

        // Second get - should return None since it's in use
        let stmt2 = cache.get(sql);
        assert!(stmt2.is_none(), "Should not return statement that's in use");

        // Return it
        cache.return_statement(sql);

        // Now it should be available again
        let stmt3 = cache.get(sql);
        assert!(stmt3.is_some());
    }

    /// Test that mark_cursor_closed works on in-use statements
    /// (the connection code returns the statement before marking closed)
    #[test]
    fn test_mark_closed_after_return() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM dual";

        cache.put(sql.to_string(), make_test_statement(sql, 100));

        // Get statement
        let _ = cache.get(sql);

        // Return it first, then mark closed
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Verify
        let stmt = cache.get(sql).expect("Should be cached");
        assert_eq!(stmt.cursor_id(), 0);
    }
}

mod statement_reuse_tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    /// Test that clone_for_reuse preserves cursor_id when non-zero
    #[test]
    fn test_clone_preserves_cursor_id() {
        let sql = "SELECT * FROM dual";
        let stmt = make_test_statement(sql, 100);

        let cloned = stmt.clone_for_reuse();
        assert_eq!(cloned.cursor_id(), 100, "clone_for_reuse should preserve cursor_id");
        assert!(cloned.executed());
    }

    /// Test that clone_for_reuse works with cursor_id = 0
    #[test]
    fn test_clone_with_zero_cursor_id() {
        let sql = "SELECT * FROM dual";
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(0);
        stmt.set_executed(false);

        let cloned = stmt.clone_for_reuse();
        assert_eq!(cloned.cursor_id(), 0);
        assert!(!cloned.executed());
    }

    /// Test the intended flow: cache hit with cursor_id=0 forces fresh cursor
    #[test]
    fn test_reuse_after_cursor_closed() {
        let mut cache = StatementCache::new(5);
        let sql = "SELECT * FROM employees";

        // First use: cursor_id = 100
        cache.put(sql.to_string(), make_test_statement(sql, 100));
        let stmt = cache.get(sql).unwrap();
        assert_eq!(stmt.cursor_id(), 100);

        // Mark closed
        cache.return_statement(sql);
        cache.mark_cursor_closed(sql);

        // Second use: cursor_id = 0, will force Execute instead of Reexecute
        let stmt = cache.get(sql).unwrap();
        assert_eq!(stmt.cursor_id(), 0, "Should have cursor_id=0 after close");

        // When this goes to ExecuteMessage, cursor_id=0 triggers FunctionCode::Execute
        // instead of FunctionCode::Reexecute, so Oracle issues a fresh cursor
    }
}

mod cache_eviction_tests {
    use super::*;

    fn make_test_statement(sql: &str, cursor_id: u16) -> Statement {
        let mut stmt = Statement::new(sql);
        stmt.set_cursor_id(cursor_id);
        stmt.set_executed(true);
        stmt
    }

    /// Test that LRU eviction doesn't affect in-use statements
    #[test]
    fn test_lru_eviction_skips_in_use() {
        let mut cache = StatementCache::new(2);

        // Add two statements
        cache.put("SELECT 1 FROM DUAL".to_string(), make_test_statement("SELECT 1 FROM DUAL", 1));
        cache.put("SELECT 2 FROM DUAL".to_string(), make_test_statement("SELECT 2 FROM DUAL", 2));

        // Mark first as in use
        let _ = cache.get("SELECT 1 FROM DUAL");

        // Add third - should evict second (LRU that's not in use)
        cache.put("SELECT 3 FROM DUAL".to_string(), make_test_statement("SELECT 3 FROM DUAL", 3));

        // First should still be there (was in use)
        cache.return_statement("SELECT 1 FROM DUAL");
        assert!(cache.get("SELECT 1 FROM DUAL").is_some());

        // Second should be evicted
        cache.return_statement("SELECT 1 FROM DUAL");
        assert!(cache.get("SELECT 2 FROM DUAL").is_none());
    }

    /// Test cache clear
    #[test]
    fn test_clear_removes_all() {
        let mut cache = StatementCache::new(5);

        cache.put("SELECT 1 FROM DUAL".to_string(), make_test_statement("SELECT 1 FROM DUAL", 1));
        cache.put("SELECT 2 FROM DUAL".to_string(), make_test_statement("SELECT 2 FROM DUAL", 2));
        cache.put("SELECT 3 FROM DUAL".to_string(), make_test_statement("SELECT 3 FROM DUAL", 3));

        assert_eq!(cache.len(), 3);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
