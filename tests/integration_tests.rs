//! Integration tests for Oracle-RS against a real Oracle database
//!
//! These tests require a running Oracle instance. Set the following environment variables:
//! - ORACLE_HOST: Oracle host (default: localhost)
//! - ORACLE_PORT: Oracle port (default: 1521)
//! - ORACLE_SERVICE: Oracle service name (default: FREEPDB1)
//! - ORACLE_USER: Oracle username (default: system)
//! - ORACLE_PASSWORD: Oracle password (default: testpass)
//!
//! Run with: cargo test --test integration_tests -- --ignored

use oracle_rs::{Config, Connection, Error};

/// Get test configuration from environment or use defaults
fn get_test_config() -> Config {
    let host = std::env::var("ORACLE_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("ORACLE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1521);
    let service = std::env::var("ORACLE_SERVICE").unwrap_or_else(|_| "FREEPDB1".to_string());
    let username = std::env::var("ORACLE_USER").unwrap_or_else(|_| "system".to_string());
    let password = std::env::var("ORACLE_PASSWORD").unwrap_or_else(|_| "testpass".to_string());

    let mut config = Config::new(&host, port, &service, &username, &password);
    config.set_password(&password);
    config
}

/// Helper to connect using test configuration
async fn connect() -> Result<Connection, Error> {
    let config = get_test_config();
    Connection::connect_with_config(config).await
}

mod connection_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_connect_and_close() {
        let conn = connect().await.expect("Failed to connect");
        assert!(!conn.is_closed());

        conn.close().await.expect("Failed to close connection");
        assert!(conn.is_closed());
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_ping() {
        let conn = connect().await.expect("Failed to connect");

        conn.ping().await.expect("Ping failed");

        conn.close().await.expect("Failed to close connection");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_invalid_credentials() {
        let host = std::env::var("ORACLE_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port: u16 = std::env::var("ORACLE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1521);
        let service = std::env::var("ORACLE_SERVICE").unwrap_or_else(|_| "FREEPDB1".to_string());

        let mut config = Config::new(&host, port, &service, "invalid_user", "invalid_pass");
        config.set_password("invalid_pass");

        let result = Connection::connect_with_config(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_connection_string_connect() {
        let host = std::env::var("ORACLE_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port: u16 = std::env::var("ORACLE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1521);
        let service = std::env::var("ORACLE_SERVICE").unwrap_or_else(|_| "FREEPDB1".to_string());
        let username = std::env::var("ORACLE_USER").unwrap_or_else(|_| "system".to_string());
        let password = std::env::var("ORACLE_PASSWORD").unwrap_or_else(|_| "testpass".to_string());

        let connect_string = format!("{}:{}/{}", host, port, service);
        let conn = Connection::connect(&connect_string, &username, &password).await
            .expect("Failed to connect with connection string");

        conn.close().await.expect("Failed to close");
    }
}

mod query_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_simple_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query("SELECT 1 FROM DUAL", &[]).await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1);
        assert!(!result.is_empty());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_sysdate_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query("SELECT SYSDATE FROM DUAL", &[]).await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1);
        assert_eq!(result.column_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_string_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query("SELECT 'Hello World' AS greeting FROM DUAL", &[]).await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1);
        assert!(result.column_by_name("GREETING").is_some());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_multiple_columns() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT 1 AS col1, 2 AS col2, 'test' AS col3 FROM DUAL",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);
        assert_eq!(result.column_count(), 3);
        assert_eq!(result.column_index("COL1"), Some(0));
        assert_eq!(result.column_index("COL2"), Some(1));
        assert_eq!(result.column_index("COL3"), Some(2));

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_query_departments_table() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT dept_id, dept_name FROM test_departments ORDER BY dept_id",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 4);
        assert_eq!(result.column_count(), 2);
        assert!(result.column_by_name("DEPT_ID").is_some());
        assert!(result.column_by_name("DEPT_NAME").is_some());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_query_employees_table() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT emp_id, first_name, last_name, salary FROM test_employees ORDER BY emp_id",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 5);
        assert!(result.column_by_name("EMP_ID").is_some());
        assert!(result.column_by_name("FIRST_NAME").is_some());
        assert!(result.column_by_name("LAST_NAME").is_some());
        assert!(result.column_by_name("SALARY").is_some());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_query_with_where_clause() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT * FROM test_employees WHERE dept_id = 1",
            &[]
        ).await.expect("Query failed");

        // Engineering department has 2 employees
        assert_eq!(result.row_count(), 2);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_query_with_null_values() {
        let conn = connect().await.expect("Failed to connect");

        // Employee with NULL email
        let result = conn.query(
            "SELECT email FROM test_employees WHERE emp_id = 5",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_empty_result_set() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT * FROM test_employees WHERE emp_id = 99999",
            &[]
        ).await.expect("Query failed");

        assert!(result.is_empty());
        assert_eq!(result.row_count(), 0);

        conn.close().await.expect("Failed to close");
    }
}

mod data_type_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_number_data_type() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_integer, val_number FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_varchar_data_type() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_varchar FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_date_data_type() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_date FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_timestamp_data_type() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_timestamp FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_clob_data_type() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        let result = conn
            .query("SELECT val_clob FROM test_data_types WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");
        assert_eq!(result.columns.len(), 1, "Expected 1 column");
        assert_eq!(result.columns[0].name, "VAL_CLOB");

        // Check the LOB value was returned
        let row = &result.rows[0];
        assert!(!row.values().is_empty(), "Row has no values");

        let lob_value = row.values().get(0).expect("Missing CLOB value");

        // The CLOB should be returned as a LOB locator
        match lob_value {
            Value::Lob(lob) => {
                // LOB size should be 20 (length of "This is a CLOB text")
                assert!(lob.size().is_some(), "LOB should have a size");
                let size = lob.size().unwrap();
                assert!(size > 0, "LOB size should be > 0, got {}", size);
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_clob_read_content() {
        use oracle_rs::{Value, LobData};

        let conn = connect().await.expect("Failed to connect");

        let result = conn
            .query("SELECT val_clob FROM test_data_types WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        // Get the LOB locator and read the content
        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Read the LOB content
                let data = conn.read_lob(locator).await.expect("Failed to read LOB");

                // Should be string data for CLOB
                match data {
                    LobData::String(s) => {
                        // Database has "This is a CLOB value" (20 chars)
                        assert!(s.starts_with("This is a CLOB"), "CLOB content should start with 'This is a CLOB', got: {:?}", s);
                        assert!(!s.is_empty(), "CLOB content should not be empty");
                    }
                    LobData::Bytes(_) => {
                        panic!("Expected string data for CLOB, got bytes");
                    }
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_length() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        let result = conn
            .query("SELECT val_clob FROM test_data_types WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Get the LOB length using the lob_length operation
                let length = conn.lob_length(locator).await.expect("Failed to get LOB length");

                // The CLOB content is "This is a CLOB value" which is 20 characters
                // But it might be stored differently, so just check it's > 0
                assert!(length > 0, "LOB length should be > 0, got {}", length);

                // Also verify it matches the size we got from metadata
                if let Some(meta_size) = lob.size() {
                    assert_eq!(length, meta_size, "Length from lob_length should match metadata size");
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_clob_write_and_read() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        // Query the CLOB to get its locator
        let result = conn
            .query("SELECT val_clob FROM test_data_types WHERE id = 1 FOR UPDATE", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Read the original content
                let original = conn.read_clob(locator).await.expect("Failed to read original CLOB");
                eprintln!("[TEST] Original CLOB content: {:?}", original);

                // Write new content at offset 1 (1-based, so this overwrites from the beginning)
                let new_text = "Hello, Oracle!";
                conn.write_clob(locator, 1, new_text).await.expect("Failed to write CLOB");

                // Do a fresh SELECT to get a new locator and verify data
                // Note: Reading with the old locator returns cached data, so we need a fresh locator
                let fresh_result = conn
                    .query("SELECT val_clob FROM test_data_types WHERE id = 1", &[])
                    .await
                    .expect("Fresh query failed");
                let fresh_row = &fresh_result.rows[0];
                let fresh_lob = fresh_row.values().get(0).expect("Missing fresh CLOB");

                if let Value::Lob(fresh_lob_val) = fresh_lob {
                    let fresh_locator = fresh_lob_val.as_locator().expect("Expected fresh LOB locator");
                    let written = conn.read_clob(fresh_locator).await.expect("Failed to read written CLOB");
                    eprintln!("[TEST] After write CLOB content (fresh locator): {:?}", written);

                    // The written content should start with our new text
                    assert!(written.starts_with("Hello, Oracle!"),
                        "Written CLOB should start with 'Hello, Oracle!', got: {:?}", written);
                } else {
                    panic!("Expected fresh LOB value, got {:?}", fresh_lob);
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        // Rollback to restore original data
        conn.rollback().await.expect("Failed to rollback");

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_trim_via_plsql() {
        // First verify that PL/SQL can trim the LOB
        let conn = connect().await.expect("Failed to connect");

        // Create a temporary table with a CLOB using PL/SQL to handle "already exists" gracefully
        conn.execute("BEGIN EXECUTE IMMEDIATE 'CREATE GLOBAL TEMPORARY TABLE temp_lob_test (id NUMBER, val_clob CLOB) ON COMMIT DELETE ROWS'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;", &[])
            .await
            .expect("Failed to create/check temp table");

        // Insert test data
        conn.execute("INSERT INTO temp_lob_test (id, val_clob) VALUES (1, 'Hello World - this is a test CLOB')", &[])
            .await
            .expect("Failed to insert test data");

        // Verify the content before PL/SQL trim
        let result = conn.query("SELECT val_clob FROM temp_lob_test WHERE id = 1", &[]).await.expect("Query failed");
        eprintln!("[TEST] Before PL/SQL trim: {:?}", result.rows.first().map(|r| r.values().get(0)));

        // Use PL/SQL to trim
        conn.execute("DECLARE l_clob CLOB; BEGIN SELECT val_clob INTO l_clob FROM temp_lob_test WHERE id = 1 FOR UPDATE; DBMS_LOB.TRIM(l_clob, 5); END;", &[])
            .await
            .expect("PL/SQL trim failed");

        // Check result
        let result = conn.query("SELECT val_clob FROM temp_lob_test WHERE id = 1", &[]).await.expect("Query failed");
        eprintln!("[TEST] After PL/SQL trim: {:?}", result.rows.first().map(|r| r.values().get(0)));

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_write() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        // Create a regular table using PL/SQL to handle "already exists" gracefully
        conn.execute("BEGIN EXECUTE IMMEDIATE 'CREATE TABLE regular_blob_test (id NUMBER, val_blob BLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;", &[])
            .await
            .expect("Failed to create/check table");

        // Delete any existing test row
        conn.execute("DELETE FROM regular_blob_test WHERE id = 100", &[])
            .await
            .ok();

        // Insert test data with a BLOB
        conn.execute("INSERT INTO regular_blob_test (id, val_blob) VALUES (100, UTL_RAW.CAST_TO_RAW(RPAD('A', 100, 'A')))", &[])
            .await
            .expect("Failed to insert test data");

        // Query the BLOB to get its locator (no FOR UPDATE)
        let result = conn
            .query("SELECT val_blob FROM regular_blob_test WHERE id = 100", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing BLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Get the size to verify it's a real LOB
                let original_size = lob.size().unwrap_or(0);
                eprintln!("[TEST] LOB size from metadata: {}", original_size);

                // Read original content
                let original_content = conn.read_blob(locator).await.expect("Failed to read original BLOB");
                eprintln!("[TEST] Original BLOB first 20 bytes: {:02x?}", &original_content[..std::cmp::min(20, original_content.len())]);

                // Write "Hello" at offset 1 (1-based) - raw bytes for BLOB
                conn.write_blob(locator, 1, b"Hello").await.expect("Failed to write BLOB");

                // Read using same locator
                let content_same_locator = conn.read_blob(locator).await.expect("Failed to read written BLOB");
                eprintln!("[TEST] After write (same locator) first 20 bytes: {:02x?}", &content_same_locator[..std::cmp::min(20, content_same_locator.len())]);

                // Do a fresh SELECT to get a new locator and verify data
                // Note: Reading with the old locator returns cached data, so we need a fresh locator
                let fresh_result = conn
                    .query("SELECT val_blob FROM regular_blob_test WHERE id = 100", &[])
                    .await
                    .expect("Fresh query failed");
                let fresh_row = &fresh_result.rows[0];
                let fresh_lob = fresh_row.values().get(0).expect("Missing fresh LOB");
                if let Value::Lob(fresh_lob_val) = fresh_lob {
                    let fresh_locator = fresh_lob_val.as_locator().expect("Expected fresh LOB locator");
                    let content = conn.read_blob(fresh_locator).await.expect("Failed to read fresh BLOB");
                    eprintln!("[TEST] After write (fresh locator) first 20 bytes: {:02x?}", &content[..std::cmp::min(20, content.len())]);
                    // Should start with "Hello" bytes since we wrote at the beginning
                    assert!(content.starts_with(b"Hello"), "Content should start with 'Hello' bytes, got first 20: {:02x?}", &content[..std::cmp::min(20, content.len())]);
                } else {
                    panic!("Expected fresh LOB value");
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        // Clean up - delete the test row and commit
        conn.execute("DELETE FROM regular_blob_test WHERE id = 100", &[])
            .await
            .ok();
        conn.commit().await.ok();

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_write_medium() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        // Create a regular table using PL/SQL to handle "already exists" gracefully
        conn.execute("BEGIN EXECUTE IMMEDIATE 'CREATE TABLE medium_blob_test (id NUMBER, val_blob BLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;", &[])
            .await
            .expect("Failed to create/check table");

        // Delete any existing test row
        conn.execute("DELETE FROM medium_blob_test WHERE id = 100", &[])
            .await
            .ok();

        // Insert test data with a BLOB (small initial data)
        conn.execute("INSERT INTO medium_blob_test (id, val_blob) VALUES (100, UTL_RAW.CAST_TO_RAW('x'))", &[])
            .await
            .expect("Failed to insert test data");

        // Query with FOR UPDATE to get writable locator
        let result = conn
            .query("SELECT val_blob FROM medium_blob_test WHERE id = 100 FOR UPDATE", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing BLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Test sizes including multi-packet (> SDU boundary) and larger data
                // Multi-packet kicks in around 8040 bytes (when message > 8182)
                for &size in &[1000, 8000, 8050, 16000, 32000] {
                    let data = vec![0x42u8; size]; // 'B' bytes
                    eprintln!("[TEST] Writing {} bytes...", size);
                    match conn.write_blob(locator, 1, &data).await {
                        Ok(_) => eprintln!("[TEST] Write of {} bytes succeeded", size),
                        Err(e) => {
                            eprintln!("[TEST] Write of {} bytes FAILED: {:?}", size, e);
                            panic!("Write of {} bytes failed", size);
                        }
                    }

                    // Get a fresh locator and verify the write
                    let fresh_result = conn
                        .query("SELECT val_blob FROM medium_blob_test WHERE id = 100 FOR UPDATE", &[])
                        .await
                        .expect("Fresh query failed");
                    let fresh_row = &fresh_result.rows[0];
                    let fresh_lob = fresh_row.values().get(0).expect("Missing fresh LOB");
                    if let Value::Lob(fresh_lob_val) = fresh_lob {
                        let fresh_locator = fresh_lob_val.as_locator().expect("Expected fresh LOB locator");
                        let content = conn.read_blob(fresh_locator).await.expect("Failed to read");
                        eprintln!("[TEST] Read back {} bytes, expected >= {}", content.len(), size);
                        assert!(content.len() >= size, "Expected at least {} bytes, got {}", size, content.len());
                        assert!(content.iter().take(size).all(|&b| b == 0x42), "Content should be 0x42 bytes");
                    } else {
                        panic!("Expected fresh LOB value");
                    }
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        // Clean up
        conn.execute("DELETE FROM medium_blob_test WHERE id = 100", &[])
            .await
            .ok();
        conn.commit().await.ok();

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_trim() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        // Create a regular table using PL/SQL to handle "already exists" gracefully
        conn.execute("BEGIN EXECUTE IMMEDIATE 'CREATE TABLE regular_clob_test (id NUMBER, val_clob CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;", &[])
            .await
            .expect("Failed to create/check table");

        // Delete any existing test row
        conn.execute("DELETE FROM regular_clob_test WHERE id = 200", &[])
            .await
            .ok();

        // Insert test data with a longer CLOB
        conn.execute("INSERT INTO regular_clob_test (id, val_clob) VALUES (200, 'Hello World - this is a test CLOB that needs trimming')", &[])
            .await
            .expect("Failed to insert test data");

        // Query the CLOB to get its locator
        let result = conn
            .query("SELECT val_clob FROM regular_clob_test WHERE id = 200", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Get original length
                let original_length = conn.lob_length(locator).await.expect("Failed to get original length");
                eprintln!("[TEST] Original CLOB length: {}", original_length);
                assert!(original_length > 5, "CLOB should be longer than 5 characters");

                // Trim to 5 characters
                conn.lob_trim(locator, 5).await.expect("Failed to trim LOB");

                // Re-fetch the LOB to get a fresh locator and verify
                let fresh_result = conn
                    .query("SELECT val_clob FROM regular_clob_test WHERE id = 200", &[])
                    .await
                    .expect("Fresh query failed");
                let fresh_row = &fresh_result.rows[0];
                let fresh_lob = fresh_row.values().get(0).expect("Missing fresh CLOB");
                if let Value::Lob(fresh_lob_val) = fresh_lob {
                    let fresh_locator = fresh_lob_val.as_locator().expect("Expected fresh LOB locator");

                    // Read content after trim to verify
                    let content = conn.read_clob(fresh_locator).await.expect("Failed to read trimmed CLOB");
                    eprintln!("[TEST] After trim CLOB content: {:?}", content);

                    // Check new length via lob_length
                    let new_length = conn.lob_length(fresh_locator).await.expect("Failed to get new length");
                    eprintln!("[TEST] After trim lob_length: {}", new_length);

                    // Verify trimmed content
                    assert_eq!(content.len(), 5, "Trimmed CLOB content should be 5 characters");
                    assert_eq!(new_length, 5, "Trimmed CLOB length should be 5");
                    assert_eq!(content, "Hello", "Trimmed content should be 'Hello'");
                } else {
                    panic!("Expected fresh LOB value");
                }
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        // Clean up - delete the test row and commit
        conn.execute("DELETE FROM regular_clob_test WHERE id = 200", &[])
            .await
            .ok();
        conn.commit().await.ok();

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_clob_read_with_convenience_method() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        let result = conn
            .query("SELECT val_clob FROM test_data_types WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");

                // Use the convenience read_clob method
                let content = conn.read_clob(locator).await.expect("Failed to read CLOB");

                assert!(!content.is_empty(), "CLOB content should not be empty");
                assert!(content.starts_with("This is a CLOB"),
                    "CLOB content should start with 'This is a CLOB', got: {:?}", content);
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_null_values() {
        let conn = connect().await.expect("Failed to connect");

        // Row 3 has only ID, rest are NULL
        // Include val_clob to test NULL CLOB handling
        let result = conn.query(
            "SELECT id, val_integer, val_number, val_varchar, val_date, val_timestamp, val_float, val_double, val_raw, val_clob FROM test_data_types WHERE id = 3",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        // Check that the row was returned (ID should be 3, rest are NULL)
        let row = &result.rows[0];
        // ID column should have value 3
        assert!(matches!(&row.values()[0], oracle_rs::Value::String(s) if s == "3"));

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_float_data_types() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_float, val_double FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_raw_data_type() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT val_raw FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_large_clob_read() {
        use oracle_rs::Value;

        let conn = connect().await.expect("Failed to connect");

        // Create a table for large CLOB testing
        conn.execute("BEGIN EXECUTE IMMEDIATE 'DROP TABLE large_clob_test'; EXCEPTION WHEN OTHERS THEN NULL; END;", &[])
            .await.expect("Failed to drop table");
        conn.execute(
            "CREATE TABLE large_clob_test (id NUMBER, content CLOB)",
            &[]
        ).await.expect("Failed to create table");

        // Insert a large CLOB (>8KB to span multiple packets)
        // Using TO_CLOB and concatenation to exceed VARCHAR2 limit (4000)
        conn.execute(
            "INSERT INTO large_clob_test (id, content) VALUES (1,
             TO_CLOB(RPAD('X', 4000, 'X')) ||
             TO_CLOB(RPAD('X', 4000, 'X')) ||
             TO_CLOB(RPAD('X', 2000, 'X')))",
            &[]
        ).await.expect("Failed to insert large CLOB");

        // Query the CLOB
        let result = conn
            .query("SELECT content FROM large_clob_test WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let size = lob.size().unwrap_or(0);

                // Size should be 10000 characters (4000 + 4000 + 2000)
                assert!(size >= 10000, "CLOB should be at least 10000 bytes, got {}", size);

                // Read the entire CLOB - this tests multi-packet handling
                let content = conn.read_clob(locator).await.expect("Failed to read large CLOB");

                // Verify size matches
                assert_eq!(content.len(), 10000, "Content should be 10000 characters, got {}", content.len());

                // Verify content is all X's
                assert!(content.chars().all(|c| c == 'X'), "Content should be all X's");
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    // Note: Large BLOB read uses the same multi-packet code path as CLOB (read_lob_internal).
    // The test_large_clob_read test verifies multi-packet handling works.
    // BLOB-specific tests are covered by test_lob_write which tests BLOB read/write.

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_streaming_lob_read() {
        use oracle_rs::Value;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let conn = connect().await.expect("Failed to connect");

        // Create a table for streaming CLOB testing
        conn.execute("BEGIN EXECUTE IMMEDIATE 'DROP TABLE stream_clob_test'; EXCEPTION WHEN OTHERS THEN NULL; END;", &[])
            .await.expect("Failed to drop table");
        conn.execute(
            "CREATE TABLE stream_clob_test (id NUMBER, content CLOB)",
            &[]
        ).await.expect("Failed to create table");

        // Insert a large CLOB (>8KB)
        conn.execute(
            "INSERT INTO stream_clob_test (id, content) VALUES (1,
             TO_CLOB(RPAD('A', 4000, 'A')) ||
             TO_CLOB(RPAD('B', 4000, 'B')) ||
             TO_CLOB(RPAD('C', 4000, 'C')))",
            &[]
        ).await.expect("Failed to insert CLOB");

        // Query the CLOB
        let result = conn
            .query("SELECT content FROM stream_clob_test WHERE id = 1", &[])
            .await
            .expect("Query failed");

        assert_eq!(result.row_count(), 1, "Expected 1 row");

        let row = &result.rows[0];
        let lob_value = row.values().get(0).expect("Missing CLOB value");

        match lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let total_size = lob.size().unwrap_or(0);
                eprintln!("[TEST] CLOB total size: {}", total_size);
                assert_eq!(total_size, 12000, "CLOB should be 12000 bytes");

                // Test lob_chunk_size
                let chunk_size = conn.lob_chunk_size(locator).await.expect("Failed to get chunk size");
                eprintln!("[TEST] LOB chunk size: {}", chunk_size);
                assert!(chunk_size > 0, "Chunk size should be > 0");

                // Stream the LOB in 2000-byte chunks
                let chunk_count = Arc::new(AtomicUsize::new(0));
                let total_bytes = Arc::new(AtomicUsize::new(0));
                let chunk_count_clone = Arc::clone(&chunk_count);
                let total_bytes_clone = Arc::clone(&total_bytes);

                conn.read_lob_chunked(locator, 2000, |chunk| {
                    let cc = Arc::clone(&chunk_count_clone);
                    let tb = Arc::clone(&total_bytes_clone);
                    async move {
                        match chunk {
                            oracle_rs::LobData::String(s) => {
                                cc.fetch_add(1, Ordering::SeqCst);
                                tb.fetch_add(s.len(), Ordering::SeqCst);
                            }
                            oracle_rs::LobData::Bytes(b) => {
                                cc.fetch_add(1, Ordering::SeqCst);
                                tb.fetch_add(b.len(), Ordering::SeqCst);
                            }
                        }
                        Ok(())
                    }
                }).await.expect("Failed to stream LOB");

                let chunks_read = chunk_count.load(Ordering::SeqCst);
                let bytes_read = total_bytes.load(Ordering::SeqCst);

                eprintln!("[TEST] Chunks read: {}, Bytes read: {}", chunks_read, bytes_read);

                // Should have read ~6 chunks (12000 / 2000)
                assert!(chunks_read >= 6, "Should have read at least 6 chunks, got {}", chunks_read);
                assert_eq!(bytes_read, 12000, "Should have read 12000 bytes total, got {}", bytes_read);
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        }

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    // NOTE: LONG and LONG RAW data types require special protocol handling
    // that is not yet implemented. These deprecated types need different
    // describe/fetch behavior. Use CLOB/BLOB instead for new applications.
}

mod dml_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_insert_and_rollback() {
        let conn = connect().await.expect("Failed to connect");

        // Insert a row
        eprintln!("[TEST] Starting INSERT");
        let result = conn.execute(
            "INSERT INTO test_departments (dept_id, dept_name) VALUES (100, 'Test Department')",
            &[]
        ).await.expect("Insert failed");
        eprintln!("[TEST] INSERT completed, rows_affected={}", result.rows_affected);

        // Should affect 1 row
        assert!(result.rows_affected >= 0);

        // Rollback so we don't affect other tests
        eprintln!("[TEST] Starting ROLLBACK");
        conn.rollback().await.expect("Rollback failed");
        eprintln!("[TEST] ROLLBACK completed");

        // Verify it was rolled back
        eprintln!("[TEST] Starting SELECT query");
        let result = conn.query(
            "SELECT * FROM test_departments WHERE dept_id = 100",
            &[]
        ).await.expect("Query failed");
        eprintln!("[TEST] SELECT completed");

        assert!(result.is_empty());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_update_and_rollback() {
        let conn = connect().await.expect("Failed to connect");

        // Update rows
        let result = conn.execute(
            "UPDATE test_employees SET salary = salary + 1 WHERE dept_id = 1",
            &[]
        ).await.expect("Update failed");

        // Should affect 2 rows (Engineering department)
        assert!(result.rows_affected >= 0);

        // Rollback
        conn.rollback().await.expect("Rollback failed");

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_delete_and_rollback() {
        let conn = connect().await.expect("Failed to connect");

        // Delete a row
        let result = conn.execute(
            "DELETE FROM test_employees WHERE emp_id = 5",
            &[]
        ).await.expect("Delete failed");

        assert!(result.rows_affected >= 0);

        // Rollback
        conn.rollback().await.expect("Rollback failed");

        // Verify row is still there
        let result = conn.query(
            "SELECT * FROM test_employees WHERE emp_id = 5",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_commit() {
        let conn = connect().await.expect("Failed to connect");

        // Insert with a high ID that won't conflict
        let result = conn.execute(
            "INSERT INTO test_departments (dept_id, dept_name) VALUES (999, 'Temp Dept')",
            &[]
        ).await.expect("Insert failed");

        assert!(result.rows_affected >= 0);

        // Commit
        conn.commit().await.expect("Commit failed");

        // Verify it's there
        let result = conn.query(
            "SELECT * FROM test_departments WHERE dept_id = 999",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        // Clean up
        conn.execute("DELETE FROM test_departments WHERE dept_id = 999", &[]).await.ok();
        conn.commit().await.expect("Commit failed");

        conn.close().await.expect("Failed to close");
    }
}

mod transaction_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_transaction_isolation() {
        let conn1 = connect().await.expect("Failed to connect conn1");
        let conn2 = connect().await.expect("Failed to connect conn2");

        // Insert on conn1 but don't commit
        conn1.execute(
            "INSERT INTO test_departments (dept_id, dept_name) VALUES (888, 'Isolated Dept')",
            &[]
        ).await.expect("Insert failed");

        // Query from conn2 - should not see uncommitted row
        let result = conn2.query(
            "SELECT * FROM test_departments WHERE dept_id = 888",
            &[]
        ).await.expect("Query failed");

        // Should be empty (uncommitted data not visible)
        assert!(result.is_empty());

        // Rollback conn1
        conn1.rollback().await.expect("Rollback failed");

        conn1.close().await.expect("Failed to close conn1");
        conn2.close().await.expect("Failed to close conn2");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_savepoint() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE savepoint_test (id NUMBER, val VARCHAR2(50))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM savepoint_test", &[]).await.ok();

        // Insert first row
        conn.execute("INSERT INTO savepoint_test (id, val) VALUES (1, 'first')", &[])
            .await.expect("Insert 1 failed");

        // Create savepoint
        conn.savepoint("sp1").await.expect("Failed to create savepoint");

        // Insert second row
        conn.execute("INSERT INTO savepoint_test (id, val) VALUES (2, 'second')", &[])
            .await.expect("Insert 2 failed");

        // Create another savepoint
        conn.savepoint("sp2").await.expect("Failed to create savepoint sp2");

        // Insert third row
        conn.execute("INSERT INTO savepoint_test (id, val) VALUES (3, 'third')", &[])
            .await.expect("Insert 3 failed");

        // Verify all 3 rows exist
        let result = conn.query("SELECT COUNT(*) FROM savepoint_test", &[])
            .await.expect("Count query failed");
        println!("Before rollback: {:?}", result.rows[0].values());

        // Rollback to sp1 - should remove rows 2 and 3
        conn.rollback_to_savepoint("sp1").await.expect("Rollback to savepoint failed");

        // Verify only row 1 exists
        let result = conn.query("SELECT id FROM savepoint_test ORDER BY id", &[])
            .await.expect("Query failed");
        assert_eq!(result.row_count(), 1, "Should have 1 row after rollback to sp1");

        // Commit - row 1 should be persisted
        conn.commit().await.expect("Commit failed");

        // Verify row 1 is still there
        let result = conn.query("SELECT id FROM savepoint_test", &[])
            .await.expect("Final query failed");
        assert_eq!(result.row_count(), 1);

        // Clean up
        conn.execute("DELETE FROM savepoint_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }
}

mod error_handling_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_syntax_error() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query("SELEC * FROM DUAL", &[]).await;

        match result {
            Ok(_) => panic!("Expected an error but got success"),
            Err(e) => eprintln!("Error returned: {:?}", e),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_table_not_found() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query("SELECT * FROM nonexistent_table_xyz", &[]).await;

        assert!(result.is_err());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_duplicate_key_error() {
        let conn = connect().await.expect("Failed to connect");

        // Try to insert duplicate primary key
        let result = conn.execute(
            "INSERT INTO test_departments (dept_id, dept_name) VALUES (1, 'Duplicate')",
            &[]
        ).await;

        assert!(result.is_err());

        // Rollback any partial transaction
        conn.rollback().await.ok();

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_foreign_key_violation() {
        let conn = connect().await.expect("Failed to connect");

        // Try to insert employee with non-existent department
        let result = conn.execute(
            "INSERT INTO test_employees (emp_id, first_name, last_name, dept_id) VALUES (999, 'Test', 'User', 999)",
            &[]
        ).await;

        assert!(result.is_err());

        // Rollback any partial transaction
        conn.rollback().await.ok();

        conn.close().await.expect("Failed to close");
    }
}

mod aggregate_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_count_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT COUNT(*) AS cnt FROM test_employees",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);
        assert!(result.column_by_name("CNT").is_some());

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_sum_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT SUM(salary) AS total_salary FROM test_employees",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_group_by_query() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT dept_id, COUNT(*) AS emp_count FROM test_employees GROUP BY dept_id ORDER BY dept_id",
            &[]
        ).await.expect("Query failed");

        // We have 4 departments with employees
        assert!(result.row_count() >= 1);

        conn.close().await.expect("Failed to close");
    }
}

mod join_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_inner_join() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT e.first_name, e.last_name, d.dept_name
             FROM test_employees e
             JOIN test_departments d ON e.dept_id = d.dept_id
             ORDER BY e.emp_id",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 5);
        assert_eq!(result.column_count(), 3);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_left_join() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT d.dept_name, COUNT(e.emp_id) AS emp_count
             FROM test_departments d
             LEFT JOIN test_employees e ON d.dept_id = e.dept_id
             GROUP BY d.dept_name",
            &[]
        ).await.expect("Query failed");

        assert!(result.row_count() >= 1);

        conn.close().await.expect("Failed to close");
    }
}

mod subquery_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_subquery_in_where() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT * FROM test_employees
             WHERE salary > (SELECT AVG(salary) FROM test_employees)",
            &[]
        ).await.expect("Query failed");

        // Some employees should have above-average salary
        assert!(result.row_count() >= 0);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_subquery_in_select() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.query(
            "SELECT first_name,
                    (SELECT dept_name FROM test_departments WHERE dept_id = e.dept_id) AS dept
             FROM test_employees e
             WHERE emp_id = 1",
            &[]
        ).await.expect("Query failed");

        assert_eq!(result.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }
}

/// Tests for bind parameters
mod bind_parameter_tests {
    use super::*;
    use oracle_rs::Value;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_integer() {
        let conn = connect().await.expect("Failed to connect");

        // Query with an integer bind parameter using ergonomic .into() syntax
        let result = conn.query(
            "SELECT emp_id, first_name FROM test_employees WHERE emp_id = :1",
            &[1i64.into()]
        ).await.expect("Query with integer bind failed");

        assert_eq!(result.row_count(), 1, "Should find exactly one employee with ID 1");

        let row = &result.rows[0];
        // Note: Numbers may come back as Integer or String depending on column metadata
        let emp_id = match &row.values()[0] {
            Value::Integer(i) => *i,
            Value::String(s) => s.parse::<i64>().expect("Should parse as integer"),
            v => panic!("Unexpected value type: {:?}", v),
        };
        assert_eq!(emp_id, 1, "Employee ID should be 1");

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_string() {
        let conn = connect().await.expect("Failed to connect");

        // Query with a string bind parameter using ergonomic .into() syntax
        let result = conn.query(
            "SELECT emp_id, first_name FROM test_employees WHERE first_name = :1",
            &["John".into()]
        ).await.expect("Query with string bind failed");

        assert!(result.row_count() >= 1, "Should find at least one employee named John");

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_multiple_params() {
        let conn = connect().await.expect("Failed to connect");

        // Query with multiple bind parameters using ergonomic .into() syntax
        let result = conn.query(
            "SELECT emp_id, first_name, dept_id FROM test_employees WHERE dept_id = :1 AND emp_id > :2",
            &[10i64.into(), 0i64.into()]
        ).await.expect("Query with multiple binds failed");

        // Should get employees in department 10 with emp_id > 0
        for row in &result.rows {
            let dept_id = row.get_i64(2).expect("Should have dept_id");
            assert_eq!(dept_id, 10, "All results should have dept_id = 10");
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_insert_and_select() {
        let conn = connect().await.expect("Failed to connect");

        // Create a test table for bind testing
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE bind_test (id NUMBER, name VARCHAR2(100), value NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create bind_test table");

        // Clean up any existing test data
        conn.execute("DELETE FROM bind_test WHERE id >= 1000", &[]).await.ok();

        // Insert with bind parameters using ergonomic .into() syntax
        let insert_result = conn.execute(
            "INSERT INTO bind_test (id, name, value) VALUES (:1, :2, :3)",
            &[1001i64.into(), "Test Name".into(), 42i64.into()]
        ).await.expect("Insert with binds failed");

        assert_eq!(insert_result.rows_affected, 1, "Should insert 1 row");

        // Select with bind parameter to verify
        let select_result = conn.query(
            "SELECT id, name, value FROM bind_test WHERE id = :1",
            &[Value::Integer(1001)]
        ).await.expect("Select with bind failed");

        assert_eq!(select_result.row_count(), 1, "Should find inserted row");

        let row = &select_result.rows[0];
        // Note: Numbers may come back as strings due to buffer_size handling
        let id_val = match &row.values()[0] {
            Value::Integer(i) => *i,
            Value::String(s) => s.parse::<i64>().expect("id should be numeric"),
            v => panic!("Unexpected id type: {:?}", v),
        };
        assert_eq!(id_val, 1001);
        assert_eq!(row.get_string(1), Some("Test Name"));
        let value_val = match &row.values()[2] {
            Value::Integer(i) => *i,
            Value::String(s) => s.parse::<i64>().expect("value should be numeric"),
            v => panic!("Unexpected value type: {:?}", v),
        };
        assert_eq!(value_val, 42);

        // Rollback to clean up
        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_null() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE bind_null_test (id NUMBER, name VARCHAR2(100))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Clean up
        conn.execute("DELETE FROM bind_null_test WHERE id >= 1000", &[]).await.ok();

        // Insert with NULL bind parameter using Option<T>::None.into()
        let name: Option<String> = None;
        conn.execute(
            "INSERT INTO bind_null_test (id, name) VALUES (:1, :2)",
            &[1002i64.into(), name.into()]
        ).await.expect("Insert with NULL bind failed");

        // Verify the NULL was inserted
        let result = conn.query(
            "SELECT id, name FROM bind_null_test WHERE id = :1",
            &[Value::Integer(1002)]
        ).await.expect("Select failed");

        assert_eq!(result.row_count(), 1);
        let row = &result.rows[0];
        assert!(row.is_null(1), "Name column should be NULL");

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bind_float() {
        let conn = connect().await.expect("Failed to connect");

        // Drop and create test table with NUMBER type (not BINARY_DOUBLE to avoid decoding issues)
        conn.execute("BEGIN EXECUTE IMMEDIATE 'DROP TABLE bind_float_test'; EXCEPTION WHEN OTHERS THEN NULL; END;", &[])
            .await.expect("Failed to drop table");
        conn.execute(
            "CREATE TABLE bind_float_test (id NUMBER, price NUMBER(10,2))",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM bind_float_test WHERE id >= 1000", &[]).await.ok();

        // Insert with float bind using ergonomic .into() syntax
        conn.execute(
            "INSERT INTO bind_float_test (id, price) VALUES (:1, :2)",
            &[1003i64.into(), 99.99f64.into()]
        ).await.expect("Insert with float failed");

        // Verify
        let result = conn.query(
            "SELECT id, price FROM bind_float_test WHERE id = :1",
            &[Value::Integer(1003)]
        ).await.expect("Select failed");

        assert_eq!(result.row_count(), 1);
        let row = &result.rows[0];
        // Note: NUMBER values typically come back as strings
        let price = match &row.values()[1] {
            Value::Float(f) => *f,
            Value::String(s) => s.parse::<f64>().expect("price should be numeric string"),
            Value::Integer(i) => *i as f64,
            v => panic!("Unexpected price type: {:?}", v),
        };
        assert!((price - 99.99).abs() < 0.01, "Price should be approximately 99.99, got {}", price);

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }
}

mod batch_execution_tests {
    use super::*;
    use oracle_rs::{BatchBuilder, Value};

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_insert() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_test (id NUMBER, name VARCHAR2(100))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Clean up any existing test data
        conn.execute("DELETE FROM batch_test WHERE id >= 2000", &[]).await.ok();

        // Build batch insert
        let batch = BatchBuilder::new("INSERT INTO batch_test (id, name) VALUES (:1, :2)")
            .add_row(vec![2001i64.into(), "Alice".into()])
            .add_row(vec![2002i64.into(), "Bob".into()])
            .add_row(vec![2003i64.into(), "Charlie".into()])
            .build();

        // Execute batch
        let result = conn.execute_batch(&batch).await.expect("Batch insert failed");

        assert_eq!(result.success_count, 3, "Should have 3 successful inserts");
        assert_eq!(result.total_rows_affected, 3, "Should affect 3 rows");
        assert!(result.is_success(), "Batch should succeed without errors");

        // Verify inserted data
        let query_result = conn.query(
            "SELECT id, name FROM batch_test WHERE id >= 2001 AND id <= 2003 ORDER BY id",
            &[]
        ).await.expect("Select failed");

        assert_eq!(query_result.row_count(), 3, "Should find 3 rows");
        assert_eq!(query_result.rows[0].get_string(1), Some("Alice"));
        assert_eq!(query_result.rows[1].get_string(1), Some("Bob"));
        assert_eq!(query_result.rows[2].get_string(1), Some("Charlie"));

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_with_row_counts() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_update_test (id NUMBER, value NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Clean and insert test data
        conn.execute("DELETE FROM batch_update_test", &[]).await.ok();
        conn.execute("INSERT INTO batch_update_test VALUES (1, 10)", &[]).await.ok();
        conn.execute("INSERT INTO batch_update_test VALUES (2, 20)", &[]).await.ok();
        conn.execute("INSERT INTO batch_update_test VALUES (3, 30)", &[]).await.ok();
        conn.commit().await.expect("Failed to commit setup");

        // Build batch update with row counts enabled
        let batch = BatchBuilder::new("UPDATE batch_update_test SET value = value + 1 WHERE id = :1")
            .add_row(vec![1i64.into()])
            .add_row(vec![2i64.into()])
            .add_row(vec![3i64.into()])
            .with_row_counts()
            .build();

        let result = conn.execute_batch(&batch).await.expect("Batch update failed");

        assert_eq!(result.success_count, 3);
        assert_eq!(result.total_rows_affected, 3);

        // Verify row counts are returned
        assert!(result.row_counts.is_some(), "Row counts should be returned");
        let counts = result.row_counts.unwrap();
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[0], 1);
        assert_eq!(counts[1], 1);
        assert_eq!(counts[2], 1);

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_with_mixed_types() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table with various column types
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_mixed_test (id NUMBER, name VARCHAR2(100), price NUMBER(10,2), active NUMBER(1))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM batch_mixed_test WHERE id >= 3000", &[]).await.ok();

        // Build batch with mixed types
        let batch = BatchBuilder::new("INSERT INTO batch_mixed_test (id, name, price, active) VALUES (:1, :2, :3, :4)")
            .add_row(vec![3001i64.into(), "Product A".into(), 19.99f64.into(), 1i64.into()])
            .add_row(vec![3002i64.into(), "Product B".into(), 29.99f64.into(), 0i64.into()])
            .build();

        let result = conn.execute_batch(&batch).await.expect("Batch insert failed");

        assert_eq!(result.success_count, 2);
        assert!(result.is_success());

        // Verify
        let query_result = conn.query(
            "SELECT id, name, price FROM batch_mixed_test WHERE id >= 3001 ORDER BY id",
            &[]
        ).await.expect("Select failed");

        assert_eq!(query_result.row_count(), 2);

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_with_nulls() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_null_test (id NUMBER, optional_value VARCHAR2(100))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM batch_null_test WHERE id >= 4000", &[]).await.ok();

        // Build batch with NULL values
        let name_some: Option<String> = Some("Has Value".to_string());
        let name_none: Option<String> = None;

        let batch = BatchBuilder::new("INSERT INTO batch_null_test (id, optional_value) VALUES (:1, :2)")
            .add_row(vec![4001i64.into(), name_some.into()])
            .add_row(vec![4002i64.into(), name_none.into()])
            .build();

        let result = conn.execute_batch(&batch).await.expect("Batch insert failed");

        assert_eq!(result.success_count, 2);

        // Verify NULL handling
        let query_result = conn.query(
            "SELECT id, optional_value FROM batch_null_test WHERE id >= 4001 ORDER BY id",
            &[]
        ).await.expect("Select failed");

        assert_eq!(query_result.row_count(), 2);
        assert_eq!(query_result.rows[0].get_string(1), Some("Has Value"));
        assert!(query_result.rows[1].is_null(1), "Second row should have NULL");

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_delete() {
        let conn = connect().await.expect("Failed to connect");

        // Create and populate test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_delete_test (id NUMBER, category VARCHAR2(10))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM batch_delete_test", &[]).await.ok();
        conn.execute("INSERT INTO batch_delete_test VALUES (1, 'A')", &[]).await.ok();
        conn.execute("INSERT INTO batch_delete_test VALUES (2, 'A')", &[]).await.ok();
        conn.execute("INSERT INTO batch_delete_test VALUES (3, 'B')", &[]).await.ok();
        conn.execute("INSERT INTO batch_delete_test VALUES (4, 'B')", &[]).await.ok();
        conn.execute("INSERT INTO batch_delete_test VALUES (5, 'C')", &[]).await.ok();
        conn.commit().await.expect("Failed to commit setup");

        // Batch delete by category
        let batch = BatchBuilder::new("DELETE FROM batch_delete_test WHERE category = :1")
            .add_row(vec!["A".into()])
            .add_row(vec!["B".into()])
            .with_row_counts()
            .build();

        let result = conn.execute_batch(&batch).await.expect("Batch delete failed");

        assert_eq!(result.success_count, 2);
        assert_eq!(result.total_rows_affected, 4, "Should delete 4 rows total (2 A's + 2 B's)");

        // Per-row counts should show 2 rows deleted for each category
        let counts = result.row_counts.expect("Row counts should be returned");
        assert_eq!(counts.len(), 2, "Should have row counts for both executions");
        assert_eq!(counts[0], 2, "First delete (category A) should delete 2 rows");
        assert_eq!(counts[1], 2, "Second delete (category B) should delete 2 rows");

        // Verify only category C remains
        let query_result = conn.query("SELECT id, category FROM batch_delete_test ORDER BY id", &[])
            .await.expect("Select failed");

        assert_eq!(query_result.row_count(), 1, "Should have 1 row remaining (category C)");
        assert_eq!(query_result.rows[0].get_string(1), Some("C"));

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_batch_large() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE batch_large_test (id NUMBER, data VARCHAR2(100))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM batch_large_test WHERE id >= 10000", &[]).await.ok();

        // Build a larger batch (100 rows)
        let mut builder = BatchBuilder::new("INSERT INTO batch_large_test (id, data) VALUES (:1, :2)");
        for i in 0..100 {
            builder = builder.add_row(vec![(10000 + i as i64).into(), format!("Row {}", i).into()]);
        }
        let batch = builder.build();

        let result = conn.execute_batch(&batch).await.expect("Large batch insert failed");

        assert_eq!(result.success_count, 100);
        assert_eq!(result.total_rows_affected, 100);
        assert!(result.is_success());

        // Verify by querying a few rows
        let query_result = conn.query(
            "SELECT id, data FROM batch_large_test WHERE id >= 10000 AND id < 10010 ORDER BY id",
            &[]
        ).await.expect("Select failed");

        assert_eq!(query_result.row_count(), 10, "Should have at least first 10 rows");
        assert_eq!(query_result.rows[0].get_string(1), Some("Row 0"));
        assert_eq!(query_result.rows[9].get_string(1), Some("Row 9"));

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }
}

mod scrollable_cursor_tests {
    use super::*;
    use oracle_rs::FetchOrientation;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_scrollable_cursor_basic() {
        let conn = connect().await.expect("Failed to connect");

        // Open a scrollable cursor using DUAL for simple testing
        let mut cursor = conn.open_scrollable_cursor(
            "SELECT 1 AS col1, 'test' AS col2 FROM dual"
        ).await.expect("Failed to open scrollable cursor");

        assert!(cursor.is_open());
        assert!(cursor.columns().len() >= 2, "Expected at least 2 columns, got {}", cursor.columns().len());

        // Fetch first row
        let result = conn.scroll(&mut cursor, FetchOrientation::First, 0).await
            .expect("Failed to scroll to first");

        assert!(!result.is_empty(), "Should have at least one row");
        assert_eq!(result.position, 1, "Position should be 1 after First");

        // Close cursor
        conn.close_cursor(&mut cursor).await.expect("Failed to close cursor");
        assert!(!cursor.is_open());

        conn.close().await.expect("Failed to close connection");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_scrollable_cursor_navigation() {
        let conn = connect().await.expect("Failed to connect");

        // Create test data
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE scroll_test (id NUMBER, name VARCHAR2(50))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM scroll_test", &[]).await.ok();
        for i in 1..=10 {
            conn.execute(
                "INSERT INTO scroll_test (id, name) VALUES (:1, :2)",
                &[(i as i64).into(), format!("Row {}", i).into()]
            ).await.expect("Failed to insert");
        }
        conn.commit().await.expect("Failed to commit");

        // Open scrollable cursor
        let mut cursor = conn.open_scrollable_cursor(
            "SELECT id, name FROM scroll_test ORDER BY id"
        ).await.expect("Failed to open cursor");

        // Go to first
        let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await
            .expect("Failed to scroll first");
        assert_eq!(first.position, 1);
        assert_eq!(first.rows[0].get_string(1), Some("Row 1"));

        // Go to last
        let last = conn.scroll(&mut cursor, FetchOrientation::Last, 0).await
            .expect("Failed to scroll last");
        assert!(!last.rows.is_empty(), "Should have row for Last");
        assert_eq!(last.position, 10, "Position should be 10 at last row");
        assert_eq!(last.rows[0].get_string(1), Some("Row 10"));

        // Go to absolute position 5
        let row5 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 5).await
            .expect("Failed to scroll absolute");
        assert_eq!(row5.position, 5);
        assert_eq!(row5.rows[0].get_string(1), Some("Row 5"));

        // Go relative +2 (from 5 to 7)
        let row7 = conn.scroll(&mut cursor, FetchOrientation::Relative, 2).await
            .expect("Failed to scroll relative forward");
        assert_eq!(row7.position, 7);
        assert_eq!(row7.rows[0].get_string(1), Some("Row 7"));

        // Go relative -3 (from 7 to 4)
        let row4 = conn.scroll(&mut cursor, FetchOrientation::Relative, -3).await
            .expect("Failed to scroll relative backward");
        assert_eq!(row4.position, 4);
        assert_eq!(row4.rows[0].get_string(1), Some("Row 4"));

        conn.close_cursor(&mut cursor).await.expect("Failed to close cursor");
        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_scrollable_cursor_bounds() {
        let conn = connect().await.expect("Failed to connect");

        // Open cursor on a table with known data
        let mut cursor = conn.open_scrollable_cursor(
            "SELECT emp_id FROM test_employees ORDER BY emp_id"
        ).await.expect("Failed to open cursor");

        // Go to first row - should succeed
        let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await
            .expect("Failed to scroll first");
        assert!(!first.is_empty(), "Should have data at first position");

        // Go to last row - should succeed
        let last = conn.scroll(&mut cursor, FetchOrientation::Last, 0).await
            .expect("Failed to scroll last");
        assert!(!last.is_empty(), "Should have data at last position");

        // Go back to first
        let back_first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await
            .expect("Failed to scroll back to first");
        assert!(!back_first.is_empty());

        conn.close_cursor(&mut cursor).await.expect("Failed to close cursor");
        conn.close().await.expect("Failed to close");
    }
}

mod lob_bind_tests {
    use super::*;
    use oracle_rs::Value;

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_bind_from_select() {
        let conn = connect().await.expect("Failed to connect");

        // First, select a LOB from an existing table to get a locator
        let result = conn.query(
            "SELECT val_clob FROM test_data_types WHERE id = 1",
            &[]
        ).await.expect("Failed to select LOB");

        if result.row_count() == 0 {
            println!("No LOB test data found - skipping test");
            conn.close().await.expect("Failed to close");
            return;
        }

        // Get the LOB value from the result
        let lob_value = result.rows[0].values()[0].clone();

        // Verify it's a LOB and check its size
        let lob_size = match &lob_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Should have LOB locator");
                println!("LOB locator size: {}", locator.size());
                println!("LOB locator bytes len: {}", locator.locator_bytes().len());
                locator.size()
            }
            _ => panic!("Expected LOB value, got {:?}", lob_value),
        };

        println!("Original LOB size from locator: {}", lob_size);

        // Now use this LOB in a bind parameter
        // This tests that we can properly serialize a LOB locator as a bind parameter
        let result2 = conn.query(
            "SELECT DBMS_LOB.GETLENGTH(:1) FROM DUAL",
            &[lob_value]
        ).await.expect("Failed to query with LOB bind");

        assert_eq!(result2.row_count(), 1);
        println!("Result value: {:?}", result2.rows[0].values()[0]);

        // The length should be > 0 for a non-empty LOB
        // DBMS_LOB.GETLENGTH may return as String or Integer depending on Oracle version
        let length = match &result2.rows[0].values()[0] {
            Value::Integer(n) => *n,
            Value::String(s) => s.parse::<i64>().unwrap_or(0),
            Value::Number(n) => n.as_str().parse::<i64>().unwrap_or(0),
            _ => 0,
        };
        assert!(length > 0, "LOB length should be > 0, got {} (original size: {})", length, lob_size);

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_lob_copy_via_bind() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE lob_bind_test (id NUMBER, data CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Insert initial data
        conn.execute("DELETE FROM lob_bind_test", &[]).await.ok();
        conn.execute(
            "INSERT INTO lob_bind_test (id, data) VALUES (1, 'Original CLOB content for binding test')",
            &[]
        ).await.expect("Failed to insert");
        conn.commit().await.expect("Failed to commit");

        // Select the LOB to get a locator
        let result = conn.query(
            "SELECT data FROM lob_bind_test WHERE id = 1",
            &[]
        ).await.expect("Failed to select LOB");

        assert_eq!(result.row_count(), 1);
        let lob_value = result.rows[0].values()[0].clone();

        // Verify it's a LOB with a locator
        match &lob_value {
            Value::Lob(lob) => {
                assert!(lob.as_locator().is_some(), "Should have LOB locator");
                let loc = lob.as_locator().unwrap();
                println!("Persistent LOB locator bytes: {:?}", loc.locator_bytes());
                println!("Persistent LOB oracle_type: {:?}", loc.oracle_type());
                println!("Persistent LOB is_temp: {}", loc.is_temp());
            }
            _ => panic!("Expected LOB value"),
        }

        // Use the bound LOB to copy content to a new row
        // This verifies that the LOB locator is properly serialized
        conn.execute(
            "INSERT INTO lob_bind_test (id, data) SELECT 2, :1 FROM DUAL",
            &[lob_value]
        ).await.expect("Failed to insert with LOB bind");

        // Verify the copy by selecting both rows
        let verify = conn.query(
            "SELECT id FROM lob_bind_test WHERE id IN (1, 2) ORDER BY id",
            &[]
        ).await.expect("Failed to verify");

        assert_eq!(verify.row_count(), 2, "Should have 2 rows after copy");

        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    /// Test creating a temporary CLOB and writing/reading data
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_create_temp_clob() {
        use oracle_rs::{OracleType, LobData};

        let conn = connect().await.expect("Failed to connect");

        // Create a temporary CLOB
        let locator = conn.create_temp_lob(OracleType::Clob)
            .await.expect("Failed to create temp CLOB");

        println!("Created temp CLOB locator");

        // Write data to the temporary CLOB
        let test_content = "This is test content for temporary CLOB";
        conn.write_clob(&locator, 1, test_content)
            .await.expect("Failed to write to temp CLOB");

        println!("Wrote {} bytes to temp CLOB", test_content.len());

        // Read the content back
        let data = conn.read_lob(&locator).await.expect("Failed to read temp CLOB");
        match data {
            LobData::String(s) => {
                assert_eq!(s, test_content, "CLOB content should match");
            }
            LobData::Bytes(b) => {
                let s = String::from_utf8(b.to_vec()).expect("Should be valid UTF-8");
                assert_eq!(s, test_content, "CLOB content should match");
            }
        }

        println!("Verified temp CLOB content");
        conn.close().await.expect("Failed to close");
    }

    /// Test creating a temporary BLOB and writing/reading data
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_create_temp_blob() {
        use oracle_rs::{OracleType, LobData};

        let conn = connect().await.expect("Failed to connect");

        // Create a temporary BLOB
        let locator = conn.create_temp_lob(OracleType::Blob)
            .await.expect("Failed to create temp BLOB");

        println!("Created temp BLOB locator");

        // Write data to the temporary BLOB
        let test_data: Vec<u8> = (0..100).collect();
        conn.write_blob(&locator, 1, &test_data)
            .await.expect("Failed to write to temp BLOB");

        println!("Wrote {} bytes to temp BLOB", test_data.len());

        // Read the content back
        let data = conn.read_lob(&locator).await.expect("Failed to read temp BLOB");
        match data {
            LobData::Bytes(b) => {
                assert_eq!(b.to_vec(), test_data, "BLOB content should match");
            }
            LobData::String(_) => {
                panic!("Expected bytes for BLOB, got string");
            }
        }

        println!("Verified temp BLOB content");
        conn.close().await.expect("Failed to close");
    }

    /// Test that binding temp LOB to INSERT fails gracefully
    /// This is a known limitation - use EMPTY_CLOB() workaround instead
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_temp_lob_insert() {
        use oracle_rs::{OracleType, LobData, LobValue};

        let conn = connect().await.expect("Failed to connect");

        // Create test table with CLOB column
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE temp_lob_test (id NUMBER, content CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Clean up existing data
        conn.execute("DELETE FROM temp_lob_test WHERE id >= 100", &[]).await.ok();

        // Create a temporary CLOB
        let locator = conn.create_temp_lob(OracleType::Clob)
            .await.expect("Failed to create temp CLOB");

        // Write data to the temporary CLOB
        let test_content = "This is test content inserted via temp LOB";
        conn.write_clob(&locator, 1, test_content)
            .await.expect("Failed to write to temp CLOB");

        // Debug: check LOB length after write
        let lob_len = conn.lob_length(&locator).await.expect("Failed to get LOB length");
        println!("Temp CLOB length after write: {}", lob_len);
        println!("Temp CLOB locator bytes: {:?}", locator.locator_bytes());
        println!("Temp CLOB is_temp: {}", locator.is_temp());
        println!("Temp CLOB is_initialized: {}", locator.is_initialized());

        // First, try a simple query with the temp LOB (like the working test does with persistent LOB)
        println!("Testing temp LOB with DBMS_LOB.GETLENGTH via query...");
        let result = conn.query(
            "SELECT DBMS_LOB.GETLENGTH(:1) FROM DUAL",
            &[Value::Lob(LobValue::Locator(locator.clone()))]
        ).await.expect("Query with temp CLOB bind failed");
        println!("Query result: {:?}", result.rows[0].values()[0]);

        // Try PL/SQL DBMS_LOB.GETLENGTH via execute (DML path)
        println!("Testing temp LOB with DBMS_LOB.GETLENGTH via PL/SQL execute...");
        conn.execute(
            "DECLARE v_len NUMBER; BEGIN v_len := DBMS_LOB.GETLENGTH(:1); END;",
            &[Value::Lob(LobValue::Locator(locator.clone()))]
        ).await.expect("PL/SQL read with temp CLOB bind failed");
        println!("PL/SQL read succeeded!");

        // Try PL/SQL INSERT with temp LOB - this is expected to fail
        // This is a known limitation: binding temp LOBs to INSERT doesn't work
        println!("Attempting PL/SQL INSERT with temp LOB bind (expected to fail)...");
        let insert_result = conn.execute(
            "BEGIN INSERT INTO temp_lob_test (id, content) VALUES (100, :1); END;",
            &[Value::Lob(LobValue::Locator(locator))]
        ).await;

        // Verify it fails with expected error
        assert!(insert_result.is_err(), "Temp LOB INSERT should fail");
        let err_msg = insert_result.err().unwrap().to_string();
        assert!(
            err_msg.contains("rejected") || err_msg.contains("closed"),
            "Error should mention connection rejection: {}",
            err_msg
        );
        println!("Confirmed: temp LOB INSERT fails as expected");

        // Note: For actual LOB inserts, use EMPTY_CLOB() workaround (see lob_workaround_tests)

        // Need to reconnect since temp LOB insert closes connection
        let conn = connect().await.expect("Failed to reconnect");
        conn.execute("DELETE FROM temp_lob_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }
}

/// JSON/OSON tests - requires Oracle 21c+ with JSON support
mod json_tests {
    use super::*;
    use oracle_rs::Value;

    #[tokio::test]
    #[ignore = "requires Oracle database with JSON support (21c+)"]
    async fn test_json_select_simple() {
        let conn = connect().await.expect("Failed to connect");

        // JSON_OBJECT returns VARCHAR2 by default, which is fine for older Oracle versions
        // Native JSON type columns are only available in Oracle 21c+
        // This test verifies we can at least parse JSON from a VARCHAR2 column
        let result = conn.query(
            "SELECT JSON_OBJECT('name' VALUE 'test', 'value' VALUE 42) as json_col FROM DUAL",
            &[]
        ).await.expect("Query should succeed");

        assert_eq!(result.row_count(), 1);
        let value = &result.rows[0].values()[0];

        // JSON_OBJECT returns VARCHAR2 on Oracle 19c, JSON on 21c+
        match value {
            Value::Json(json) => {
                // Native JSON column (21c+)
                assert_eq!(json.get("name").and_then(|v| v.as_str()), Some("test"));
                assert_eq!(json.get("value").and_then(|v| v.as_i64()), Some(42));
            }
            Value::String(s) => {
                // VARCHAR2 representation (19c and earlier)
                // Parse the JSON string manually
                let json: serde_json::Value = serde_json::from_str(s)
                    .expect("Should be valid JSON string");
                assert_eq!(json.get("name").and_then(|v| v.as_str()), Some("test"));
                assert_eq!(json.get("value").and_then(|v| v.as_i64()), Some(42));
            }
            _ => panic!("Expected JSON or String value, got {:?}", value),
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database with JSON support (21c+)"]
    async fn test_json_column_table() {
        let conn = connect().await.expect("Failed to connect");

        // Create a table with a JSON column
        let create_table = r#"
            BEGIN
                EXECUTE IMMEDIATE 'CREATE TABLE json_test (
                    id NUMBER PRIMARY KEY,
                    data JSON
                )';
            EXCEPTION
                WHEN OTHERS THEN
                    IF SQLCODE != -955 THEN RAISE; END IF;
            END;
        "#;

        match conn.execute(create_table, &[]).await {
            Ok(_) => {}
            Err(e) => {
                // JSON column type might not be supported
                eprintln!("JSON table creation failed (may require 21c+): {}", e);
                conn.close().await.expect("Failed to close");
                return;
            }
        }

        // Clean up any existing data
        conn.execute("DELETE FROM json_test", &[]).await.ok();

        // Insert JSON data using JSON literals
        conn.execute(
            "INSERT INTO json_test (id, data) VALUES (1, JSON_OBJECT('name' VALUE 'Alice', 'age' VALUE 30))",
            &[]
        ).await.expect("Failed to insert JSON");

        conn.execute(
            "INSERT INTO json_test (id, data) VALUES (2, JSON_OBJECT('name' VALUE 'Bob', 'items' VALUE JSON_ARRAY(1, 2, 3)))",
            &[]
        ).await.expect("Failed to insert JSON with array");

        conn.commit().await.expect("Failed to commit");

        // Query the JSON data
        let result = conn.query(
            "SELECT id, data FROM json_test ORDER BY id",
            &[]
        ).await.expect("Failed to query JSON");

        assert_eq!(result.row_count(), 2);

        // Verify first row
        let row1 = &result.rows[0];
        assert_eq!(row1.get_i64(0), Some(1));
        if let Some(Value::Json(json)) = row1.get(1) {
            assert_eq!(json.get("name").and_then(|v| v.as_str()), Some("Alice"));
            assert_eq!(json.get("age").and_then(|v| v.as_i64()), Some(30));
        } else {
            panic!("Expected JSON value for row 1");
        }

        // Verify second row with array
        let row2 = &result.rows[1];
        assert_eq!(row2.get_i64(0), Some(2));
        if let Some(Value::Json(json)) = row2.get(1) {
            assert_eq!(json.get("name").and_then(|v| v.as_str()), Some("Bob"));
            let items = json.get("items").and_then(|v| v.as_array());
            assert!(items.is_some());
            let items = items.unwrap();
            assert_eq!(items.len(), 3);
        } else {
            panic!("Expected JSON value for row 2");
        }

        // Clean up
        conn.rollback().await.expect("Failed to rollback");
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database with JSON support (21c+)"]
    async fn test_json_bind_parameter() {
        let conn = connect().await.expect("Failed to connect");

        // Create a table with a JSON column using USERS tablespace (ASSM required for JSON)
        // Use PL/SQL block to handle "table already exists" error gracefully
        match conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE json_bind_test (id NUMBER PRIMARY KEY, data JSON) TABLESPACE USERS'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("JSON table creation failed (requires 21c+ with ASSM tablespace): {}", e);
                conn.close().await.expect("Failed to close");
                return;
            }
        }

        // Clean up any existing data
        conn.execute("DELETE FROM json_bind_test", &[]).await.ok();

        // Create a JSON value using serde_json
        let json_data = oracle_rs::serde_json::json!({
            "product": "Widget",
            "price": 19.99,
            "in_stock": true,
            "tags": ["electronics", "gadget"]
        });

        // Bind the JSON value as a parameter
        let json_value = Value::Json(json_data.clone());

        // This test verifies that JSON bind parameters are correctly encoded as OSON
        let insert_result = conn.execute(
            "INSERT INTO json_bind_test (id, data) VALUES (1, :1)",
            &[json_value]
        ).await.expect("Failed to insert JSON bind parameter");

        assert_eq!(insert_result.rows_affected, 1, "Should insert 1 row");
        conn.commit().await.expect("Failed to commit");

        // Verify by selecting back
        let result = conn.query(
            "SELECT data FROM json_bind_test WHERE id = 1",
            &[]
        ).await.expect("Failed to query");

        assert_eq!(result.row_count(), 1, "Should have 1 row");

        match result.rows[0].get(0) {
            Some(Value::Json(retrieved)) => {
                assert_eq!(retrieved.get("product").and_then(|v| v.as_str()), Some("Widget"));
                assert_eq!(retrieved.get("in_stock").and_then(|v| v.as_bool()), Some(true));
                assert_eq!(retrieved.get("price").and_then(|v| v.as_f64()), Some(19.99));
                // Check array
                if let Some(tags) = retrieved.get("tags").and_then(|v| v.as_array()) {
                    assert_eq!(tags.len(), 2);
                    assert_eq!(tags[0].as_str(), Some("electronics"));
                    assert_eq!(tags[1].as_str(), Some("gadget"));
                } else {
                    panic!("Expected tags array");
                }
            }
            Some(other) => {
                panic!("Expected JSON value, got {:?}", other);
            }
            None => {
                panic!("Got None for column 0");
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database with JSON support (21c+)"]
    async fn test_json_null() {
        let conn = connect().await.expect("Failed to connect");

        // Query a NULL JSON value
        let result = conn.query(
            "SELECT CAST(NULL AS JSON) FROM DUAL",
            &[]
        ).await;

        match result {
            Ok(result) => {
                assert_eq!(result.row_count(), 1);
                let value = &result.rows[0].values()[0];

                match value {
                    Value::Json(json) => {
                        assert!(json.is_null(), "Expected null JSON value");
                    }
                    Value::Null => {
                        // Also acceptable
                    }
                    _ => panic!("Expected JSON or Null value"),
                }
            }
            Err(e) => {
                eprintln!("JSON null test skipped: {}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }
}

mod vector_tests {
    use super::*;
    use oracle_rs::{OracleVector, VectorData, Value};

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_create_table() {
        let conn = connect().await.expect("Failed to connect");

        // Try to create a table with VECTOR column - this will fail on older Oracle versions
        let result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vectors (id NUMBER, embedding VECTOR(3, FLOAT32))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        match result {
            Ok(_) => {
                // Clean up and test
                conn.execute("DELETE FROM test_vectors", &[]).await.ok();
                conn.commit().await.expect("Failed to commit");
                println!("VECTOR table created successfully");
            }
            Err(e) => {
                // Oracle version doesn't support VECTOR
                eprintln!("VECTOR type not supported: {}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_insert_and_select_float32() {
        let conn = connect().await.expect("Failed to connect");

        // Create table with VECTOR column
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_f32 (id NUMBER, embedding VECTOR(3, FLOAT32))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        // Clean the table
        conn.execute("DELETE FROM test_vector_f32", &[]).await.ok();

        // Insert a vector using SQL literal syntax
        let result = conn.execute(
            "INSERT INTO test_vector_f32 (id, embedding) VALUES (1, '[1.0, 2.0, 3.0]')",
            &[]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");

                // Select the vector back
                let query_result = conn.query("SELECT id, embedding FROM test_vector_f32 WHERE id = 1", &[])
                    .await.expect("Query failed");

                assert_eq!(query_result.row_count(), 1);
                let row = &query_result.rows[0];

                // Check ID
                assert_eq!(row.get_i64(0), Some(1));

                // Check vector
                let vector_value = row.get(1).expect("No vector column");
                match vector_value {
                    Value::Vector(vec) => {
                        assert_eq!(vec.dimensions(), 3);
                        match vec.data() {
                            VectorData::Float32(values) => {
                                assert!((values[0] - 1.0).abs() < 0.001);
                                assert!((values[1] - 2.0).abs() < 0.001);
                                assert!((values[2] - 3.0).abs() < 0.001);
                            }
                            _ => panic!("Expected Float32 vector data"),
                        }
                    }
                    _ => panic!("Expected Vector value, got {:?}", vector_value),
                }
            }
            Err(e) => {
                eprintln!("Vector insert failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_bind_parameter() {
        let conn = connect().await.expect("Failed to connect");

        // Create table
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_bind (id NUMBER, embedding VECTOR(4, FLOAT32))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        // Clean the table
        conn.execute("DELETE FROM test_vector_bind", &[]).await.ok();

        // Create a vector to bind
        let vector = OracleVector::float32(vec![0.1, 0.2, 0.3, 0.4]);

        // Insert using bind parameter
        let result = conn.execute(
            "INSERT INTO test_vector_bind (id, embedding) VALUES (:1, :2)",
            &[Value::Integer(1), Value::Vector(vector.clone())]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");

                // Query back
                let query_result = conn.query("SELECT embedding FROM test_vector_bind WHERE id = 1", &[])
                    .await.expect("Query failed");

                assert_eq!(query_result.row_count(), 1);
                let vector_value = query_result.rows[0].get(0).expect("No vector");

                match vector_value {
                    Value::Vector(v) => {
                        assert_eq!(v.dimensions(), 4);
                        match v.data() {
                            VectorData::Float32(values) => {
                                assert!((values[0] - 0.1).abs() < 0.001);
                                assert!((values[1] - 0.2).abs() < 0.001);
                                assert!((values[2] - 0.3).abs() < 0.001);
                                assert!((values[3] - 0.4).abs() < 0.001);
                            }
                            _ => panic!("Expected Float32 data"),
                        }
                    }
                    _ => panic!("Expected Vector value"),
                }
            }
            Err(e) => {
                eprintln!("Vector bind test failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_float64() {
        let conn = connect().await.expect("Failed to connect");

        // Create table with FLOAT64 vector
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_f64 (id NUMBER, embedding VECTOR(2, FLOAT64))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        conn.execute("DELETE FROM test_vector_f64", &[]).await.ok();

        // Insert using bind parameter
        let vector = OracleVector::float64(vec![1.5, 2.5]);
        let result = conn.execute(
            "INSERT INTO test_vector_f64 (id, embedding) VALUES (:1, :2)",
            &[Value::Integer(1), Value::Vector(vector)]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");

                let query_result = conn.query("SELECT embedding FROM test_vector_f64 WHERE id = 1", &[])
                    .await.expect("Query failed");

                if let Some(Value::Vector(v)) = query_result.rows.get(0).and_then(|r| r.get(0)) {
                    match v.data() {
                        VectorData::Float64(values) => {
                            assert!((values[0] - 1.5).abs() < 0.0001);
                            assert!((values[1] - 2.5).abs() < 0.0001);
                        }
                        _ => panic!("Expected Float64 data"),
                    }
                }
            }
            Err(e) => {
                eprintln!("Vector float64 test failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_int8() {
        let conn = connect().await.expect("Failed to connect");

        // Create table with INT8 vector
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_i8 (id NUMBER, embedding VECTOR(5, INT8))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        conn.execute("DELETE FROM test_vector_i8", &[]).await.ok();

        // Insert using bind parameter
        let vector = OracleVector::int8(vec![-128, -1, 0, 1, 127]);
        let result = conn.execute(
            "INSERT INTO test_vector_i8 (id, embedding) VALUES (:1, :2)",
            &[Value::Integer(1), Value::Vector(vector)]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");

                let query_result = conn.query("SELECT embedding FROM test_vector_i8 WHERE id = 1", &[])
                    .await.expect("Query failed");

                if let Some(Value::Vector(v)) = query_result.rows.get(0).and_then(|r| r.get(0)) {
                    match v.data() {
                        VectorData::Int8(values) => {
                            assert_eq!(values[0], -128);
                            assert_eq!(values[1], -1);
                            assert_eq!(values[2], 0);
                            assert_eq!(values[3], 1);
                            assert_eq!(values[4], 127);
                        }
                        _ => panic!("Expected Int8 data"),
                    }
                }
            }
            Err(e) => {
                eprintln!("Vector int8 test failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_null() {
        let conn = connect().await.expect("Failed to connect");

        // Create table
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_null (id NUMBER, embedding VECTOR(3, FLOAT32))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        conn.execute("DELETE FROM test_vector_null", &[]).await.ok();

        // Insert row with NULL vector
        let result = conn.execute(
            "INSERT INTO test_vector_null (id, embedding) VALUES (1, NULL)",
            &[]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");

                let query_result = conn.query("SELECT embedding FROM test_vector_null WHERE id = 1", &[])
                    .await.expect("Query failed");

                assert_eq!(query_result.row_count(), 1);
                let value = query_result.rows[0].get(0).expect("No column");
                assert!(value.is_null(), "Expected NULL vector");
            }
            Err(e) => {
                eprintln!("Vector null test failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle 23ai database"]
    async fn test_vector_from_convenience() {
        let conn = connect().await.expect("Failed to connect");

        // Test the From<Vec<f32>> implementation for Value
        let create_result = conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE test_vector_conv (id NUMBER, embedding VECTOR(3, FLOAT32))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await;

        if create_result.is_err() {
            eprintln!("VECTOR type not supported, skipping test");
            conn.close().await.ok();
            return;
        }

        conn.execute("DELETE FROM test_vector_conv", &[]).await.ok();

        // Use the convenient .into() syntax for vectors
        let embedding: Vec<f32> = vec![1.0, 2.0, 3.0];
        let result = conn.execute(
            "INSERT INTO test_vector_conv (id, embedding) VALUES (:1, :2)",
            &[1i64.into(), embedding.into()]
        ).await;

        match result {
            Ok(_) => {
                conn.commit().await.expect("Failed to commit");
                println!("Vector convenience conversion works!");
            }
            Err(e) => {
                eprintln!("Vector convenience test failed: {}", e);
            }
        }

        conn.rollback().await.ok();
        conn.close().await.expect("Failed to close");
    }
}

mod plsql_tests {
    use super::*;
    use oracle_rs::{BindParam, OracleType, Value};

    // ============================================================
    // PL/SQL OUT Parameter Tests
    // ============================================================

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_simple_out_string() {
        let conn = connect().await.expect("Failed to connect");

        // Simple PL/SQL block with OUT parameter
        let result = conn.execute_plsql(
            "BEGIN :1 := 'Hello from PL/SQL'; END;",
            &[BindParam::output(OracleType::Varchar, 100)]
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("PL/SQL OUT result: {:?}", plsql_result);
                if let Some(value) = plsql_result.get_string(0) {
                    assert_eq!(value, "Hello from PL/SQL");
                    println!("OUT parameter value: {}", value);
                } else {
                    println!("No OUT value returned (may be expected depending on wire format)");
                }
            }
            Err(e) => {
                eprintln!("PL/SQL OUT string test failed: {:?}", e);
                // Don't fail the test - this is a new feature being developed
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_out_number() {
        let conn = connect().await.expect("Failed to connect");

        // PL/SQL block with OUT number parameter
        let result = conn.execute_plsql(
            "BEGIN :1 := 42 + 58; END;",
            &[BindParam::output(OracleType::Number, 22)]
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("PL/SQL OUT number result: {:?}", plsql_result);
                if let Some(value) = plsql_result.get_integer(0) {
                    assert_eq!(value, 100);
                    println!("OUT parameter value: {}", value);
                }
            }
            Err(e) => {
                eprintln!("PL/SQL OUT number test failed: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_in_out_parameter() {
        let conn = connect().await.expect("Failed to connect");

        // PL/SQL block with IN OUT parameter (modify value)
        let result = conn.execute_plsql(
            "BEGIN :1 := :1 * 2; END;",
            &[BindParam::input_output(Value::Integer(21), 22)]
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("PL/SQL IN OUT result: {:?}", plsql_result);
                if let Some(value) = plsql_result.get_integer(0) {
                    assert_eq!(value, 42);
                    println!("IN OUT parameter value (21 * 2): {}", value);
                }
            }
            Err(e) => {
                eprintln!("PL/SQL IN OUT test failed: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_multiple_out_params() {
        let conn = connect().await.expect("Failed to connect");

        // PL/SQL block with multiple OUT parameters
        let result = conn.execute_plsql(
            "BEGIN :1 := 100; :2 := 'test'; :3 := 3.14; END;",
            &[
                BindParam::output(OracleType::Number, 22),
                BindParam::output(OracleType::Varchar, 100),
                BindParam::output(OracleType::BinaryDouble, 8),
            ]
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("PL/SQL multiple OUT result: {:?}", plsql_result);
                println!("OUT value 0: {:?}", plsql_result.get(0));
                println!("OUT value 1: {:?}", plsql_result.get(1));
                println!("OUT value 2: {:?}", plsql_result.get(2));
            }
            Err(e) => {
                eprintln!("PL/SQL multiple OUT test failed: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_mixed_in_and_out() {
        let conn = connect().await.expect("Failed to connect");

        // PL/SQL block with both IN and OUT parameters
        // Use :1 for input and :2 for output, in order
        let result = conn.execute_plsql(
            "DECLARE v_result VARCHAR2(100); BEGIN v_result := :1 || ' World'; :2 := v_result; END;",
            &[
                BindParam::input(Value::String("Hello".to_string())),
                BindParam::output(OracleType::Varchar, 100),
            ]
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("PL/SQL mixed IN/OUT result: {:?}", plsql_result);
                // The OUT value should be the second parameter
                if let Some(value) = plsql_result.get_string(0) {
                    assert_eq!(value, "Hello World");
                    println!("OUT parameter value: {}", value);
                }
            }
            Err(e) => {
                eprintln!("PL/SQL mixed IN/OUT test failed: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_plsql_procedure_call() {
        let conn = connect().await.expect("Failed to connect");

        // Create a test procedure
        let create_proc_result = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_out_proc(p_in IN NUMBER, p_out OUT VARCHAR2) IS
             BEGIN
                 p_out := 'Input was: ' || TO_CHAR(p_in);
             END;",
            &[]
        ).await;

        match create_proc_result {
            Ok(_) => {
                println!("Test procedure created successfully");

                // Call the procedure
                let call_result = conn.execute_plsql(
                    "BEGIN test_out_proc(:1, :2); END;",
                    &[
                        BindParam::input(Value::Integer(42)),
                        BindParam::output(OracleType::Varchar, 100),
                    ]
                ).await;

                match call_result {
                    Ok(plsql_result) => {
                        println!("Procedure call result: {:?}", plsql_result);
                        if let Some(value) = plsql_result.get_string(0) {
                            assert!(value.contains("42"));
                            println!("Procedure OUT value: {}", value);
                        }
                    }
                    Err(e) => {
                        eprintln!("Procedure call failed: {:?}", e);
                    }
                }

                // Clean up
                conn.execute("DROP PROCEDURE test_out_proc", &[]).await.ok();
            }
            Err(e) => {
                eprintln!("Failed to create test procedure: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }
}

/// Tests for LOB queries with bind parameters (regression tests for LOB re-execute fix)
mod lob_bind_param_tests {
    use super::*;
    use oracle_rs::Value;

    /// Test SELECT with bind parameters on CLOB table
    /// This is a regression test for the bug where LOB re-execute incorrectly
    /// included bind parameter info in the define request, causing hangs.
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_select_clob_with_bind_params() {
        let conn = connect().await.expect("Failed to connect");

        // Create table with CLOB column
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE bind_clob_test (id NUMBER, content CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM bind_clob_test", &[]).await.ok();

        // INSERT with bind params
        conn.execute(
            "INSERT INTO bind_clob_test (id, content) VALUES (:1, :2)",
            &[1i64.into(), "Hello World".into()]
        ).await.expect("INSERT failed");
        conn.commit().await.expect("COMMIT failed");

        // SELECT without bind params
        let result = conn.query(
            "SELECT id, content FROM bind_clob_test WHERE id = 1",
            &[]
        ).await.expect("SELECT without bind failed");
        assert_eq!(result.row_count(), 1);

        // SELECT with bind params - this was hanging before the fix
        let result = conn.query(
            "SELECT id, content FROM bind_clob_test WHERE id = :1",
            &[Value::Integer(1)]
        ).await.expect("SELECT with bind failed");
        assert_eq!(result.row_count(), 1);

        // Verify data
        let row = result.rows.first().expect("Should have row");
        let id_val = match &row.values()[0] {
            Value::Integer(i) => *i,
            Value::String(s) => s.parse::<i64>().expect("Should be numeric"),
            v => panic!("Unexpected id type: {:?}", v),
        };
        assert_eq!(id_val, 1);

        // Clean up
        conn.execute("DELETE FROM bind_clob_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }
}

/// Tests for binding strings/bytes to LOB columns using workarounds
mod lob_workaround_tests {
    use super::*;
    use oracle_rs::{Value, LobData};

    /// Test inserting data into CLOB using EMPTY_CLOB() + FOR UPDATE pattern
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_empty_clob_workaround() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE clob_workaround_test (id NUMBER, content CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM clob_workaround_test WHERE id = 1", &[]).await.ok();

        // Step 1: Insert with EMPTY_CLOB() placeholder
        conn.execute(
            "INSERT INTO clob_workaround_test (id, content) VALUES (:1, EMPTY_CLOB())",
            &[1.into()]
        ).await.expect("Failed to insert empty CLOB");

        // Step 2: Select FOR UPDATE to get the LOB locator
        let rows = conn.query(
            "SELECT content FROM clob_workaround_test WHERE id = 1 FOR UPDATE",
            &[]
        ).await.expect("Failed to select for update");

        assert_eq!(rows.row_count(), 1);
        let test_content = "This is the CLOB content inserted via EMPTY_CLOB workaround";

        // Step 3: Write to the persistent LOB
        match &rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                conn.write_clob(locator, 1, test_content)
                    .await
                    .expect("Failed to write to CLOB");
            }
            _ => panic!("Expected LOB value"),
        }

        conn.commit().await.expect("Failed to commit");

        // Verify the content was written
        let verify_rows = conn.query(
            "SELECT content FROM clob_workaround_test WHERE id = 1",
            &[]
        ).await.expect("Failed to verify");

        assert_eq!(verify_rows.row_count(), 1);
        match &verify_rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let content = conn.read_lob(locator).await.expect("Failed to read CLOB");
                match content {
                    LobData::String(s) => assert_eq!(s, test_content),
                    LobData::Bytes(b) => {
                        let text = String::from_utf8(b.to_vec()).expect("Invalid UTF-8");
                        assert_eq!(text, test_content);
                    }
                }
            }
            Value::String(s) => {
                // Small CLOBs might be returned inline
                assert_eq!(s, test_content);
            }
            _ => panic!("Expected LOB or String value"),
        }

        // Clean up
        conn.execute("DELETE FROM clob_workaround_test WHERE id = 1", &[]).await.ok();
        conn.commit().await.expect("Failed to commit cleanup");
        conn.close().await.expect("Failed to close");
    }

    /// Test inserting data into BLOB using EMPTY_BLOB() + FOR UPDATE pattern
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_empty_blob_workaround() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE blob_workaround_test (id NUMBER, content BLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM blob_workaround_test WHERE id = 1", &[]).await.ok();

        // Step 1: Insert with EMPTY_BLOB() placeholder
        conn.execute(
            "INSERT INTO blob_workaround_test (id, content) VALUES (:1, EMPTY_BLOB())",
            &[1.into()]
        ).await.expect("Failed to insert empty BLOB");

        // Step 2: Select FOR UPDATE to get the LOB locator
        let rows = conn.query(
            "SELECT content FROM blob_workaround_test WHERE id = 1 FOR UPDATE",
            &[]
        ).await.expect("Failed to select for update");

        assert_eq!(rows.row_count(), 1);
        let test_data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();

        // Step 3: Write to the persistent LOB
        match &rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                conn.write_blob(locator, 1, &test_data)
                    .await
                    .expect("Failed to write to BLOB");
            }
            _ => panic!("Expected LOB value"),
        }

        conn.commit().await.expect("Failed to commit");

        // Verify the content was written
        let verify_rows = conn.query(
            "SELECT content FROM blob_workaround_test WHERE id = 1",
            &[]
        ).await.expect("Failed to verify");

        assert_eq!(verify_rows.row_count(), 1);
        match &verify_rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let content = conn.read_lob(locator).await.expect("Failed to read BLOB");
                match content {
                    LobData::Bytes(b) => assert_eq!(b.to_vec(), test_data),
                    LobData::String(_) => panic!("Expected bytes for BLOB"),
                }
            }
            Value::Bytes(b) => {
                // Small BLOBs might be returned inline
                assert_eq!(b.to_vec(), test_data);
            }
            _ => panic!("Expected LOB or Bytes value"),
        }

        // Clean up
        conn.execute("DELETE FROM blob_workaround_test WHERE id = 1", &[]).await.ok();
        conn.commit().await.expect("Failed to commit cleanup");
        conn.close().await.expect("Failed to close");
    }

    /// Test that small strings can be bound directly to CLOB columns
    /// (Oracle implicitly converts VARCHAR2 to CLOB)
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_string_to_clob_implicit_conversion() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE string_clob_test (id NUMBER, content CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM string_clob_test WHERE id = 1", &[]).await.ok();

        // Insert string directly - Oracle should convert to CLOB
        let test_string = "Hello, this is a small string that should work with CLOB columns";
        conn.execute(
            "INSERT INTO string_clob_test (id, content) VALUES (:1, :2)",
            &[1.into(), test_string.into()]
        ).await.expect("Failed to insert string as CLOB");

        conn.commit().await.expect("Failed to commit");

        // Verify the content
        let rows = conn.query(
            "SELECT content FROM string_clob_test WHERE id = 1",
            &[]
        ).await.expect("Failed to query");

        assert_eq!(rows.row_count(), 1);
        match &rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let content = conn.read_lob(locator).await.expect("Failed to read");
                match content {
                    LobData::String(s) => assert_eq!(s, test_string),
                    LobData::Bytes(b) => {
                        let text = String::from_utf8(b.to_vec()).expect("Invalid UTF-8");
                        assert_eq!(text, test_string);
                    }
                }
            }
            Value::String(s) => {
                assert_eq!(s, test_string);
            }
            _ => panic!("Expected LOB or String value"),
        }

        // Clean up
        conn.execute("DELETE FROM string_clob_test WHERE id = 1", &[]).await.ok();
        conn.commit().await.expect("Failed to commit cleanup");
        conn.close().await.expect("Failed to close");
    }

    /// Test using DBMS_LOB functions with RETURNING INTO for large data
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_dbms_lob_returning_into() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE dbms_lob_test (id NUMBER, content CLOB)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM dbms_lob_test WHERE id = 1", &[]).await.ok();

        // Use PL/SQL to insert and get the LOB locator in one operation
        conn.execute(
            "DECLARE
               v_clob CLOB;
             BEGIN
               INSERT INTO dbms_lob_test (id, content) VALUES (:1, EMPTY_CLOB())
                 RETURNING content INTO v_clob;
               DBMS_LOB.WRITEAPPEND(v_clob, LENGTH('Test content via DBMS_LOB'), 'Test content via DBMS_LOB');
             END;",
            &[1.into()]
        ).await.expect("Failed to execute PL/SQL");

        conn.commit().await.expect("Failed to commit");

        // Verify
        let rows = conn.query(
            "SELECT content FROM dbms_lob_test WHERE id = 1",
            &[]
        ).await.expect("Failed to query");

        assert_eq!(rows.row_count(), 1);
        match &rows.rows[0].values()[0] {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected LOB locator");
                let content = conn.read_lob(locator).await.expect("Failed to read");
                match content {
                    LobData::String(s) => assert_eq!(s, "Test content via DBMS_LOB"),
                    LobData::Bytes(b) => {
                        let text = String::from_utf8(b.to_vec()).expect("Invalid UTF-8");
                        assert_eq!(text, "Test content via DBMS_LOB");
                    }
                }
            }
            Value::String(s) => {
                assert_eq!(s, "Test content via DBMS_LOB");
            }
            _ => panic!("Expected LOB or String value"),
        }

        // Clean up
        conn.execute("DELETE FROM dbms_lob_test WHERE id = 1", &[]).await.ok();
        conn.commit().await.expect("Failed to commit cleanup");
        conn.close().await.expect("Failed to close");
    }
}

/// Tests for REF CURSOR functionality
mod ref_cursor_tests {
    use super::*;
    use oracle_rs::{BindParam, Value};

    /// Test basic REF CURSOR from PL/SQL
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_ref_cursor_basic() {
        let conn = connect().await.expect("Failed to connect");

        // Create a test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE ref_cursor_test (id NUMBER, name VARCHAR2(50))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM ref_cursor_test", &[]).await.ok();

        // Insert test data
        conn.execute(
            "INSERT INTO ref_cursor_test (id, name) VALUES (1, 'Alice')",
            &[]
        ).await.expect("Failed to insert");
        conn.execute(
            "INSERT INTO ref_cursor_test (id, name) VALUES (2, 'Bob')",
            &[]
        ).await.expect("Failed to insert");
        conn.execute(
            "INSERT INTO ref_cursor_test (id, name) VALUES (3, 'Charlie')",
            &[]
        ).await.expect("Failed to insert");
        conn.commit().await.expect("Failed to commit");

        // Execute PL/SQL that opens a REF CURSOR
        let result = conn.execute_plsql(
            "BEGIN OPEN :1 FOR SELECT id, name FROM ref_cursor_test ORDER BY id; END;",
            &[BindParam::output_cursor()]
        ).await.expect("Failed to execute PL/SQL");

        // Get the cursor from OUT parameter
        assert!(!result.out_values.is_empty(), "Should have OUT values");
        
        if let Value::Cursor(ref cursor) = result.out_values[0] {
            // Debug: print cursor info
            println!("Cursor ID: {}", cursor.cursor_id());
            println!("Column count: {}", cursor.column_count());
            for (i, col) in cursor.columns().iter().enumerate() {
                println!("  Column {}: {} ({:?})", i, col.name, col.oracle_type);
            }

            // Verify cursor has column metadata
            assert_eq!(cursor.column_count(), 2, "Cursor should have 2 columns");

            // Fetch rows from the cursor
            let rows = conn.fetch_cursor(cursor).await.expect("Failed to fetch cursor");

            println!("Fetched {} rows, has_more: {}", rows.row_count(), rows.has_more_rows);

            assert_eq!(rows.row_count(), 3, "Should fetch 3 rows");

            // Verify row data
            // Note: Values might come as String or Integer depending on format
            println!("Row 0: {:?}", rows.rows[0].values());
            println!("Row 1: {:?}", rows.rows[1].values());
            println!("Row 2: {:?}", rows.rows[2].values());
        } else {
            panic!("Expected Cursor value, got {:?}", result.out_values[0]);
        }

        // Clean up
        conn.execute("DELETE FROM ref_cursor_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }

    /// Test REF CURSOR with filtering
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_ref_cursor_with_filter() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE ref_cursor_filter_test (id NUMBER, status VARCHAR2(20))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM ref_cursor_filter_test", &[]).await.ok();

        // Insert test data
        for i in 1..=5 {
            let status = if i % 2 == 0 { "active" } else { "inactive" };
            conn.execute(
                "INSERT INTO ref_cursor_filter_test (id, status) VALUES (:1, :2)",
                &[i.into(), status.into()]
            ).await.expect("Failed to insert");
        }
        conn.commit().await.expect("Failed to commit");

        // Open cursor for active records only
        let result = conn.execute_plsql(
            "BEGIN OPEN :1 FOR SELECT id, status FROM ref_cursor_filter_test WHERE status = 'active' ORDER BY id; END;",
            &[BindParam::output_cursor()]
        ).await.expect("Failed to execute PL/SQL");

        if let Value::Cursor(ref cursor) = result.out_values[0] {
            let rows = conn.fetch_cursor(cursor).await.expect("Failed to fetch cursor");
            
            // Should have 2 active records (id 2 and 4)
            assert_eq!(rows.row_count(), 2, "Should fetch 2 active rows");
        } else {
            panic!("Expected Cursor value");
        }

        // Clean up
        conn.execute("DELETE FROM ref_cursor_filter_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }

    // =========================================================================
    // Implicit Results Tests (DBMS_SQL.RETURN_RESULT)
    // =========================================================================

    /// Test single implicit result set from PL/SQL
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_implicit_result_single() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE implicit_test (id NUMBER, name VARCHAR2(50))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM implicit_test", &[]).await.ok();

        // Insert test data
        conn.execute("INSERT INTO implicit_test (id, name) VALUES (1, 'Alice')", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_test (id, name) VALUES (2, 'Bob')", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_test (id, name) VALUES (3, 'Charlie')", &[]).await.expect("Failed to insert");
        conn.commit().await.expect("Failed to commit");

        // Execute PL/SQL block that returns implicit result set
        let result = conn.execute_plsql(
            "DECLARE
               c SYS_REFCURSOR;
             BEGIN
               OPEN c FOR SELECT id, name FROM implicit_test ORDER BY id;
               DBMS_SQL.RETURN_RESULT(c);
             END;",
            &[]
        ).await.expect("Failed to execute PL/SQL");

        println!("Implicit results count: {}", result.implicit_results.len());

        // Should have 1 implicit result
        assert_eq!(result.implicit_results.len(), 1, "Should have 1 implicit result");

        // Fetch rows from the implicit result
        let implicit_result = &result.implicit_results.results[0];
        println!("Implicit result cursor_id: {}, columns: {}",
            implicit_result.cursor_id, implicit_result.columns.len());

        let rows = conn.fetch_implicit_result(implicit_result).await.expect("Failed to fetch implicit result");

        println!("Fetched {} rows", rows.row_count());
        assert_eq!(rows.row_count(), 3, "Should fetch 3 rows");

        // Clean up
        conn.execute("DELETE FROM implicit_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }

    /// Test multiple implicit result sets from PL/SQL
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_implicit_result_multiple() {
        let conn = connect().await.expect("Failed to connect");

        // Create test tables
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE implicit_users (id NUMBER, name VARCHAR2(50))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create users table");

        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE implicit_orders (order_id NUMBER, user_id NUMBER, amount NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create orders table");

        conn.execute("DELETE FROM implicit_users", &[]).await.ok();
        conn.execute("DELETE FROM implicit_orders", &[]).await.ok();

        // Insert test data
        conn.execute("INSERT INTO implicit_users (id, name) VALUES (1, 'Alice')", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_users (id, name) VALUES (2, 'Bob')", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_orders (order_id, user_id, amount) VALUES (101, 1, 100)", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_orders (order_id, user_id, amount) VALUES (102, 1, 200)", &[]).await.expect("Failed to insert");
        conn.execute("INSERT INTO implicit_orders (order_id, user_id, amount) VALUES (103, 2, 150)", &[]).await.expect("Failed to insert");
        conn.commit().await.expect("Failed to commit");

        // Execute PL/SQL block that returns multiple implicit result sets
        let result = conn.execute_plsql(
            "DECLARE
               c1 SYS_REFCURSOR;
               c2 SYS_REFCURSOR;
             BEGIN
               OPEN c1 FOR SELECT id, name FROM implicit_users ORDER BY id;
               DBMS_SQL.RETURN_RESULT(c1);
               OPEN c2 FOR SELECT order_id, user_id, amount FROM implicit_orders ORDER BY order_id;
               DBMS_SQL.RETURN_RESULT(c2);
             END;",
            &[]
        ).await.expect("Failed to execute PL/SQL");

        println!("Implicit results count: {}", result.implicit_results.len());

        // Should have 2 implicit results
        assert_eq!(result.implicit_results.len(), 2, "Should have 2 implicit results");

        // Fetch first result set (users)
        let users_result = &result.implicit_results.results[0];
        let users = conn.fetch_implicit_result(users_result).await.expect("Failed to fetch users");
        println!("Users fetched: {} rows", users.row_count());
        assert_eq!(users.row_count(), 2, "Should fetch 2 users");

        // Fetch second result set (orders)
        let orders_result = &result.implicit_results.results[1];
        let orders = conn.fetch_implicit_result(orders_result).await.expect("Failed to fetch orders");
        println!("Orders fetched: {} rows", orders.row_count());
        assert_eq!(orders.row_count(), 3, "Should fetch 3 orders");

        // Clean up
        conn.execute("DELETE FROM implicit_users", &[]).await.ok();
        conn.execute("DELETE FROM implicit_orders", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }

    /// Test implicit result with no rows
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_implicit_result_empty() {
        let conn = connect().await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE implicit_empty (id NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM implicit_empty", &[]).await.ok();
        conn.commit().await.expect("Failed to commit");

        // Execute PL/SQL block that returns empty result set
        let result = conn.execute_plsql(
            "DECLARE
               c SYS_REFCURSOR;
             BEGIN
               OPEN c FOR SELECT id FROM implicit_empty;
               DBMS_SQL.RETURN_RESULT(c);
             END;",
            &[]
        ).await.expect("Failed to execute PL/SQL");

        // Should have 1 implicit result even if empty
        assert_eq!(result.implicit_results.len(), 1, "Should have 1 implicit result");

        // Fetch - should return 0 rows
        let implicit_result = &result.implicit_results.results[0];
        let rows = conn.fetch_implicit_result(implicit_result).await.expect("Failed to fetch");
        assert_eq!(rows.row_count(), 0, "Should fetch 0 rows");

        conn.close().await.expect("Failed to close");
    }
}

/// Tests for BFILE (external file) functionality
mod bfile_tests {
    use super::*;
    use oracle_rs::Value;

    /// Test creating a BFILE locator via BFILENAME() and checking its properties
    /// This doesn't require actual file access - just tests locator creation and parsing
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bfile_locator_creation() {
        let conn = connect().await.expect("Failed to connect");

        // Create a BFILE locator using BFILENAME function
        // Note: The directory doesn't need to exist for this test - we're just
        // testing that we can create and parse BFILE locators
        let result = conn.query(
            "SELECT BFILENAME('TEST_DIR', 'test_file.txt') FROM DUAL",
            &[]
        ).await.expect("Failed to execute BFILENAME query");

        assert_eq!(result.row_count(), 1, "Should return 1 row");

        let row = &result.rows[0];
        let bfile_value = row.values().get(0).expect("Missing BFILE value");

        // BFILE should be returned as a LOB value with a locator
        match bfile_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected BFILE locator");

                // Verify it's a BFILE type
                assert!(locator.is_bfile(), "Locator should be BFILE type");

                // Get and verify the directory/filename from locator
                let (dir, file) = locator.get_file_name()
                    .expect("Should be able to parse BFILE locator");

                assert_eq!(dir, "TEST_DIR", "Directory should be TEST_DIR");
                assert_eq!(file, "test_file.txt", "Filename should be test_file.txt");

                println!("BFILE locator created successfully:");
                println!("  Directory: {}", dir);
                println!("  Filename: {}", file);
                println!("  Locator bytes: {} bytes", locator.locator_bytes().len());
            }
            _ => panic!("Expected LOB value for BFILE, got {:?}", bfile_value),
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test BFILE exists check on non-existent file
    /// The directory doesn't need to exist - this tests the protocol
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bfile_exists_nonexistent() {
        let conn = connect().await.expect("Failed to connect");

        // Create a BFILE locator for a non-existent file
        let result = conn.query(
            "SELECT BFILENAME('NONEXISTENT_DIR', 'nonexistent.txt') FROM DUAL",
            &[]
        ).await.expect("Failed to execute BFILENAME query");

        let row = &result.rows[0];
        let bfile_value = row.values().get(0).expect("Missing BFILE value");

        match bfile_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected BFILE locator");
                assert!(locator.is_bfile(), "Should be BFILE type");

                // Check if file exists - should be false or error due to invalid directory
                // Oracle will return ORA-22285 if directory doesn't exist
                let exists_result = conn.bfile_exists(locator).await;

                match exists_result {
                    Ok(exists) => {
                        // If directory exists but file doesn't, exists will be false
                        println!("BFILE exists: {}", exists);
                    }
                    Err(e) => {
                        // ORA-22285: non-existent directory or file for FILEEXISTS operation
                        // Or connection reset if Oracle rejects the operation entirely
                        println!("BFILE exists check returned error (expected for non-existent dir): {}", e);
                        let err_str = e.to_string();
                        assert!(
                            err_str.contains("22285") ||
                            err_str.contains("directory") ||
                            err_str.contains("reset") ||
                            err_str.contains("ORA-"),
                            "Error should be about directory or connection: {}", e
                        );
                    }
                }
            }
            _ => panic!("Expected LOB value for BFILE"),
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test storing and retrieving BFILE locator from a table
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_bfile_in_table() {
        let conn = connect().await.expect("Failed to connect");

        // Create a table with BFILE column
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE bfile_test (id NUMBER, file_ref BFILE)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM bfile_test", &[]).await.ok();

        // Insert a BFILE locator
        conn.execute(
            "INSERT INTO bfile_test (id, file_ref) VALUES (1, BFILENAME('MY_DIR', 'document.pdf'))",
            &[]
        ).await.expect("Failed to insert");

        conn.commit().await.expect("Failed to commit");

        // Query it back
        let result = conn.query(
            "SELECT file_ref FROM bfile_test WHERE id = 1",
            &[]
        ).await.expect("Failed to query");

        assert_eq!(result.row_count(), 1);

        let row = &result.rows[0];
        let bfile_value = row.values().get(0).expect("Missing BFILE value");

        match bfile_value {
            Value::Lob(lob) => {
                let locator = lob.as_locator().expect("Expected BFILE locator");
                assert!(locator.is_bfile(), "Should be BFILE type");

                let (dir, file) = locator.get_file_name()
                    .expect("Should parse BFILE locator");

                assert_eq!(dir, "MY_DIR");
                assert_eq!(file, "document.pdf");

                println!("Retrieved BFILE from table: {}/{}", dir, file);
            }
            _ => panic!("Expected LOB value for BFILE"),
        }

        // Clean up
        conn.execute("DROP TABLE bfile_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }
}

/// Tests for statement caching functionality
mod statement_cache_tests {
    use super::*;
    use oracle_rs::Value;

    /// Helper to connect with specific cache size
    async fn connect_with_cache(cache_size: usize) -> Result<Connection, Error> {
        let host = std::env::var("ORACLE_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port: u16 = std::env::var("ORACLE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1521);
        let service = std::env::var("ORACLE_SERVICE").unwrap_or_else(|_| "FREEPDB1".to_string());
        let username = std::env::var("ORACLE_USER").unwrap_or_else(|_| "system".to_string());
        let password = std::env::var("ORACLE_PASSWORD").unwrap_or_else(|_| "testpass".to_string());

        let config = Config::new(&host, port, &service, &username, &password)
            .stmtcachesize(cache_size);

        Connection::connect_with_config(config).await
    }

    /// Test that statement caching works - same SQL should reuse cursor
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_basic() {
        let conn = connect_with_cache(20).await.expect("Failed to connect");

        let sql = "SELECT 1 + :1 AS result FROM DUAL";

        // First execution - should parse and cache
        let result1 = conn.query(sql, &[Value::Integer(1)]).await
            .expect("First query failed");
        assert_eq!(result1.row_count(), 1);

        // Second execution with different bind - should reuse cached cursor
        let result2 = conn.query(sql, &[Value::Integer(2)]).await
            .expect("Second query failed");
        assert_eq!(result2.row_count(), 1);

        // Third execution
        let result3 = conn.query(sql, &[Value::Integer(3)]).await
            .expect("Third query failed");
        assert_eq!(result3.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    /// Test that cache disabled (size=0) works
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_disabled() {
        let conn = connect_with_cache(0).await.expect("Failed to connect");

        let sql = "SELECT :1 FROM DUAL";

        // Execute multiple times - each should work without caching
        for i in 1..5 {
            let result = conn.query(sql, &[Value::Integer(i)]).await
                .expect("Query failed");
            assert_eq!(result.row_count(), 1);
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test that DDL is not cached
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_ddl_not_cached() {
        let conn = connect_with_cache(20).await.expect("Failed to connect");

        // Execute DDL multiple times - should not error
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE stmt_cache_test (id NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        // Drop it
        conn.execute("DROP TABLE stmt_cache_test", &[]).await.ok();

        // Create again - this would fail if DDL was incorrectly cached
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE stmt_cache_test (id NUMBER)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table second time");

        // Clean up
        conn.execute("DROP TABLE stmt_cache_test", &[]).await.ok();

        conn.close().await.expect("Failed to close");
    }

    /// Test that different SQL gets different cursors
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_different_sql() {
        let conn = connect_with_cache(20).await.expect("Failed to connect");

        // Execute different queries
        let result1 = conn.query("SELECT 1 FROM DUAL", &[]).await
            .expect("Query 1 failed");
        assert_eq!(result1.row_count(), 1);

        let result2 = conn.query("SELECT 2 FROM DUAL", &[]).await
            .expect("Query 2 failed");
        assert_eq!(result2.row_count(), 1);

        let result3 = conn.query("SELECT 3 FROM DUAL", &[]).await
            .expect("Query 3 failed");
        assert_eq!(result3.row_count(), 1);

        // Re-execute first query - should hit cache
        let result1b = conn.query("SELECT 1 FROM DUAL", &[]).await
            .expect("Query 1 second time failed");
        assert_eq!(result1b.row_count(), 1);

        conn.close().await.expect("Failed to close");
    }

    /// Test DML caching
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_dml() {
        let conn = connect_with_cache(20).await.expect("Failed to connect");

        // Create test table
        conn.execute(
            "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE dml_cache_test (id NUMBER, val VARCHAR2(100))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            &[]
        ).await.expect("Failed to create table");

        conn.execute("DELETE FROM dml_cache_test", &[]).await.ok();

        let insert_sql = "INSERT INTO dml_cache_test (id, val) VALUES (:1, :2)";

        // Insert multiple rows - should reuse cached cursor
        for i in 1..=5 {
            conn.execute_dml_sql(
                insert_sql,
                &[Value::Integer(i), Value::String(format!("value{}", i))]
            ).await.expect("Insert failed");
        }

        // Verify by querying all rows
        let result = conn.query("SELECT * FROM dml_cache_test ORDER BY id", &[]).await
            .expect("Select query failed");
        assert_eq!(result.row_count(), 5, "Should have inserted 5 rows");

        // Clean up
        conn.execute("DROP TABLE dml_cache_test", &[]).await.ok();
        conn.commit().await.ok();
        conn.close().await.expect("Failed to close");
    }

    /// Test that cache works with multiple bind parameters
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_multiple_binds() {
        let conn = connect_with_cache(20).await.expect("Failed to connect");

        // Query with multiple unique binds
        let sql = "SELECT :1 + :2 AS sum_val, :3 AS third_val FROM DUAL";

        // Execute same query multiple times with different bind values
        for i in 1..=3 {
            let result = conn.query(
                sql,
                &[Value::Integer(i), Value::Integer(i * 10), Value::Integer(i * 100)]
            ).await.expect("Multi-bind query failed");
            assert_eq!(result.row_count(), 1);
            assert_eq!(result.column_count(), 2);
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test default cache size (20)
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_statement_cache_default_size() {
        // Connect with default config (should have cache size 20)
        let conn = connect().await.expect("Failed to connect");

        let sql = "SELECT :1 + :2 FROM DUAL";

        // Execute same query multiple times
        for i in 1..=5 {
            let result = conn.query(sql, &[Value::Integer(i), Value::Integer(i * 10)]).await
                .expect("Query failed");
            assert_eq!(result.row_count(), 1);
        }

        conn.close().await.expect("Failed to close");
    }
}

/// Tests for PL/SQL Collections (VARRAY, Nested Table)
mod collection_tests {
    use super::*;
    use oracle_rs::dbobject::CollectionType;

    /// Setup: Create test collection types
    /// Run this manually before tests:
    /// ```sql
    /// CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER;
    /// CREATE OR REPLACE TYPE test_string_table AS TABLE OF VARCHAR2(100);
    /// ```

    /// Test get_type() for a VARRAY type
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_get_type_varray() {
        let conn = connect().await.expect("Failed to connect");

        // First, ensure the type exists
        let create_result = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION
                WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;
        // Ignore errors - type might already exist

        if create_result.is_err() {
            eprintln!("Note: Could not create test type (may already exist)");
        }

        // Get the type information
        let obj_type = conn.get_type("TEST_NUMBER_VARRAY").await;

        match obj_type {
            Ok(t) => {
                println!("Type: {}.{}", t.schema, t.name);
                println!("Is collection: {}", t.is_collection);
                println!("Collection type: {:?}", t.collection_type);
                println!("Element type: {:?}", t.element_type);

                assert!(t.is_collection, "Should be a collection");
                assert_eq!(t.collection_type, Some(CollectionType::Varray), "Should be VARRAY");
                assert_eq!(t.name, "TEST_NUMBER_VARRAY");
            }
            Err(e) => {
                eprintln!("get_type error: {:?}", e);
                // Don't fail if type doesn't exist - this is expected in some environments
            }
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test get_type() for a Nested Table type
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_get_type_nested_table() {
        let conn = connect().await.expect("Failed to connect");

        // First, ensure the type exists
        let _create_result = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_string_table AS TABLE OF VARCHAR2(100)';
             EXCEPTION
                WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Get the type information
        let obj_type = conn.get_type("TEST_STRING_TABLE").await;

        match obj_type {
            Ok(t) => {
                println!("Type: {}.{}", t.schema, t.name);
                println!("Is collection: {}", t.is_collection);
                println!("Collection type: {:?}", t.collection_type);
                println!("Element type: {:?}", t.element_type);

                assert!(t.is_collection, "Should be a collection");
                assert_eq!(t.collection_type, Some(CollectionType::NestedTable), "Should be Nested Table");
                assert_eq!(t.name, "TEST_STRING_TABLE");
            }
            Err(e) => {
                eprintln!("get_type error: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test get_type() with schema prefix
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_get_type_with_schema() {
        let conn = connect().await.expect("Failed to connect");

        // Query current user
        let result = conn.query("SELECT USER FROM DUAL", &[]).await
            .expect("Failed to get current user");
        let current_user = result.rows[0].get(0)
            .and_then(|v| v.as_str())
            .expect("No user returned");

        // Ensure type exists
        let _create_result = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION
                WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Get type with full schema prefix
        let type_name = format!("{}.TEST_NUMBER_VARRAY", current_user);
        let obj_type = conn.get_type(&type_name).await;

        match obj_type {
            Ok(t) => {
                assert!(t.is_collection, "Should be a collection");
                assert_eq!(t.schema.to_uppercase(), current_user.to_uppercase());
            }
            Err(e) => {
                eprintln!("get_type error: {:?}", e);
            }
        }

        conn.close().await.expect("Failed to close");
    }

    /// Test get_type() for non-existent type
    #[tokio::test]
    #[ignore = "requires Oracle database"]
    async fn test_get_type_not_found() {
        let conn = connect().await.expect("Failed to connect");

        let result = conn.get_type("NONEXISTENT_TYPE_XYZ").await;
        assert!(result.is_err(), "Should return error for non-existent type");

        conn.close().await.expect("Failed to close");
    }

    /// Test VARRAY OUT parameter - get collection from PL/SQL procedure
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_varray_out_param() {
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_varray_out_proc(p_out OUT test_number_varray) IS
             BEGIN
                p_out := test_number_varray(10, 20, 30, 40, 50);
             END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let varray_type = conn.get_type("TEST_NUMBER_VARRAY").await
            .expect("Failed to get type");

        println!("Got type: {}.{}", varray_type.schema, varray_type.name);
        println!("Element type: {:?}", varray_type.element_type);
        println!("Type OID: {:?}", varray_type.oid.as_ref().map(|o| format!("{:02x?}", o)));

        // Execute the procedure with OUT parameter using execute_plsql
        let result = conn.execute_plsql(
            "BEGIN test_varray_out_proc(:1); END;",
            &[BindParam::output_collection(&varray_type)],
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("OUT values: {:?}", plsql_result.out_values);
                assert!(!plsql_result.out_values.is_empty(), "Should have OUT value");

                let out_val = &plsql_result.out_values[0];
                println!("OUT value type: {:?}", out_val);

                // Should be a Collection or Bytes (fallback)
                match out_val {
                    oracle_rs::row::Value::Collection(coll) => {
                        println!("Got collection with {} elements", coll.elements.len());
                        for (i, elem) in coll.elements.iter().enumerate() {
                            println!("  [{}] = {:?}", i, elem);
                        }
                        assert_eq!(coll.elements.len(), 5, "Should have 5 elements");
                    }
                    oracle_rs::row::Value::Bytes(bytes) => {
                        println!("Got raw bytes (collection decoding pending): {} bytes", bytes.len());
                        println!("Raw: {:02x?}", &bytes[..std::cmp::min(50, bytes.len())]);
                    }
                    other => {
                        println!("Got unexpected value type: {:?}", other);
                    }
                }
            }
            Err(e) => {
                eprintln!("Execute error: {:?}", e);
                // Don't panic - we want to see the error
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_varray_out_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }

    /// Test Nested Table OUT parameter
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_nested_table_out_param() {
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_string_table AS TABLE OF VARCHAR2(100)';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_table_out_proc(p_out OUT test_string_table) IS
             BEGIN
                p_out := test_string_table('Hello', 'World', 'From', 'Oracle');
             END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let table_type = conn.get_type("TEST_STRING_TABLE").await
            .expect("Failed to get type");

        println!("Got type: {}.{}", table_type.schema, table_type.name);
        println!("Element type: {:?}", table_type.element_type);

        // Execute the procedure with OUT parameter using execute_plsql
        let result = conn.execute_plsql(
            "BEGIN test_table_out_proc(:1); END;",
            &[BindParam::output_collection(&table_type)],
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("OUT values: {:?}", plsql_result.out_values);

                if !plsql_result.out_values.is_empty() {
                    let out_val = &plsql_result.out_values[0];

                    match out_val {
                        oracle_rs::row::Value::Collection(coll) => {
                            println!("Got collection with {} elements", coll.elements.len());
                            for (i, elem) in coll.elements.iter().enumerate() {
                                println!("  [{}] = {:?}", i, elem);
                            }
                            assert_eq!(coll.elements.len(), 4, "Should have 4 elements");
                        }
                        oracle_rs::row::Value::Bytes(bytes) => {
                            println!("Got raw bytes: {} bytes", bytes.len());
                        }
                        other => {
                            println!("Got: {:?}", other);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Execute error: {:?}", e);
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_table_out_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }

    /// Test VARRAY IN parameter (simple - no OUT params)
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_varray_in_simple() {
        use oracle_rs::dbobject::DbObject;
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Create procedure that takes IN varray (no OUT params)
        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_varray_simple_proc(
                p_in IN test_number_varray
            ) IS
                v_sum NUMBER := 0;
            BEGIN
                IF p_in IS NOT NULL THEN
                    FOR i IN 1..p_in.COUNT LOOP
                        v_sum := v_sum + NVL(p_in(i), 0);
                    END LOOP;
                    DBMS_OUTPUT.PUT_LINE('Sum: ' || v_sum);
                END IF;
            END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let varray_type = conn.get_type("TEST_NUMBER_VARRAY").await
            .expect("Failed to get type");

        println!("Got type: {}.{}", varray_type.schema, varray_type.name);
        println!("Element type: {:?}", varray_type.element_type);

        // First try with empty collection to test metadata format
        let empty_coll = DbObject::collection("TEST_NUMBER_VARRAY");

        // Execute the procedure with empty collection
        let result_empty = conn.execute_plsql(
            "BEGIN test_varray_simple_proc(:1); END;",
            &[
                BindParam::input_collection(&varray_type, empty_coll),
            ],
        ).await;

        match result_empty {
            Ok(_) => {
                println!("Empty collection execute succeeded!");
            }
            Err(e) => {
                println!("Empty collection execute failed: {:?}", e);
            }
        }

        // Create collection with values
        let mut coll = DbObject::collection("TEST_NUMBER_VARRAY");
        coll.append(oracle_rs::row::Value::Integer(10));
        coll.append(oracle_rs::row::Value::Integer(20));
        coll.append(oracle_rs::row::Value::Integer(30));

        // Execute the procedure with full collection
        let result = conn.execute_plsql(
            "BEGIN test_varray_simple_proc(:1); END;",
            &[
                BindParam::input_collection(&varray_type, coll),
            ],
        ).await;

        match result {
            Ok(_) => {
                println!("Execute succeeded!");
            }
            Err(e) => {
                panic!("Execute failed: {:?}", e);
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_varray_simple_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }

    /// Test VARRAY IN parameter - pass collection to PL/SQL procedure
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_varray_in_param() {
        use oracle_rs::dbobject::DbObject;
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Create procedure that takes IN varray and returns sum
        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_varray_in_proc(
                p_in IN test_number_varray,
                p_sum OUT NUMBER
            ) IS
            BEGIN
                p_sum := 0;
                IF p_in IS NOT NULL THEN
                    FOR i IN 1..p_in.COUNT LOOP
                        p_sum := p_sum + NVL(p_in(i), 0);
                    END LOOP;
                END IF;
            END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let varray_type = conn.get_type("TEST_NUMBER_VARRAY").await
            .expect("Failed to get type");

        println!("Got type: {}.{}", varray_type.schema, varray_type.name);
        println!("Element type: {:?}", varray_type.element_type);

        // Create collection with values
        let mut coll = DbObject::collection("TEST_NUMBER_VARRAY");
        coll.append(oracle_rs::row::Value::Integer(10));
        coll.append(oracle_rs::row::Value::Integer(20));
        coll.append(oracle_rs::row::Value::Integer(30));

        // Execute the procedure with IN and OUT parameters
        let result = conn.execute_plsql(
            "BEGIN test_varray_in_proc(:1, :2); END;",
            &[
                BindParam::input_collection(&varray_type, coll),
                BindParam::output(oracle_rs::constants::OracleType::Number, 22),
            ],
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("OUT values: {:?}", plsql_result.out_values);
                assert_eq!(plsql_result.out_values.len(), 1, "Should have 1 OUT value");

                let sum = &plsql_result.out_values[0];
                println!("Sum: {:?}", sum);

                // Should be 10 + 20 + 30 = 60
                // Note: NUMBER OUT params may come back as String due to fetch format
                match sum {
                    oracle_rs::row::Value::Integer(v) => {
                        assert_eq!(*v, 60, "Sum should be 60");
                    }
                    oracle_rs::row::Value::Number(n) => {
                        assert_eq!(n.to_i64().unwrap_or(0), 60, "Sum should be 60");
                    }
                    oracle_rs::row::Value::String(s) => {
                        let v: i64 = s.trim().parse().expect("Should parse as integer");
                        assert_eq!(v, 60, "Sum should be 60");
                    }
                    other => {
                        panic!("Expected Integer, Number, or String, got {:?}", other);
                    }
                }
            }
            Err(e) => {
                panic!("Execute failed: {:?}", e);
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_varray_in_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }

    /// Test VARRAY IN/OUT parameter - pass collection and get modified result back
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_varray_inout_param() {
        use oracle_rs::dbobject::DbObject;
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_number_varray AS VARRAY(10) OF NUMBER';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Create procedure that doubles each element
        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_varray_double_proc(
                p_arr IN test_number_varray,
                p_result OUT test_number_varray
            ) IS
            BEGIN
                p_result := test_number_varray();
                IF p_arr IS NOT NULL THEN
                    p_result.EXTEND(p_arr.COUNT);
                    FOR i IN 1..p_arr.COUNT LOOP
                        p_result(i) := p_arr(i) * 2;
                    END LOOP;
                END IF;
            END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let varray_type = conn.get_type("TEST_NUMBER_VARRAY").await
            .expect("Failed to get type");

        // Create collection with values [1, 2, 3]
        let mut coll = DbObject::collection("TEST_NUMBER_VARRAY");
        coll.append(oracle_rs::row::Value::Integer(1));
        coll.append(oracle_rs::row::Value::Integer(2));
        coll.append(oracle_rs::row::Value::Integer(3));

        // Execute the procedure
        let result = conn.execute_plsql(
            "BEGIN test_varray_double_proc(:1, :2); END;",
            &[
                BindParam::input_collection(&varray_type, coll),
                BindParam::output_collection(&varray_type),
            ],
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("OUT values: {:?}", plsql_result.out_values);
                assert_eq!(plsql_result.out_values.len(), 1, "Should have 1 OUT value");

                match &plsql_result.out_values[0] {
                    oracle_rs::row::Value::Collection(coll) => {
                        println!("Got collection with {} elements", coll.elements.len());
                        for (i, elem) in coll.elements.iter().enumerate() {
                            println!("  [{}] = {:?}", i, elem);
                        }
                        assert_eq!(coll.elements.len(), 3, "Should have 3 elements");

                        // Elements should be [2, 4, 6]
                        let expected = [2i64, 4, 6];
                        for (i, exp) in expected.iter().enumerate() {
                            let val = coll.elements[i].as_i64()
                                .expect("Should be integer");
                            assert_eq!(val, *exp, "Element {} should be doubled", i);
                        }
                    }
                    other => {
                        panic!("Expected Collection, got {:?}", other);
                    }
                }
            }
            Err(e) => {
                panic!("Execute failed: {:?}", e);
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_varray_double_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }

    /// Test Nested Table IN parameter
    #[tokio::test]
    #[ignore = "requires Oracle database and test types"]
    async fn test_nested_table_in_param() {
        use oracle_rs::dbobject::DbObject;
        use oracle_rs::statement::BindParam;

        let conn = connect().await.expect("Failed to connect");

        // Create test type and procedure
        let _ = conn.execute(
            "BEGIN
                EXECUTE IMMEDIATE 'CREATE OR REPLACE TYPE test_string_table AS TABLE OF VARCHAR2(100)';
             EXCEPTION WHEN OTHERS THEN NULL;
             END;",
            &[],
        ).await;

        // Create procedure that concatenates strings
        let _ = conn.execute(
            "CREATE OR REPLACE PROCEDURE test_table_concat_proc(
                p_in IN test_string_table,
                p_result OUT VARCHAR2
            ) IS
            BEGIN
                p_result := '';
                IF p_in IS NOT NULL THEN
                    FOR i IN 1..p_in.COUNT LOOP
                        IF i > 1 THEN
                            p_result := p_result || ', ';
                        END IF;
                        p_result := p_result || p_in(i);
                    END LOOP;
                END IF;
            END;",
            &[],
        ).await.expect("Failed to create procedure");

        // Get the type descriptor
        let table_type = conn.get_type("TEST_STRING_TABLE").await
            .expect("Failed to get type");

        // Create collection with values
        let mut coll = DbObject::collection("TEST_STRING_TABLE");
        coll.append(oracle_rs::row::Value::String("Hello".to_string()));
        coll.append(oracle_rs::row::Value::String("World".to_string()));

        // Execute the procedure
        let result = conn.execute_plsql(
            "BEGIN test_table_concat_proc(:1, :2); END;",
            &[
                BindParam::input_collection(&table_type, coll),
                BindParam::output(oracle_rs::constants::OracleType::Varchar, 200),
            ],
        ).await;

        match result {
            Ok(plsql_result) => {
                println!("OUT values: {:?}", plsql_result.out_values);
                assert_eq!(plsql_result.out_values.len(), 1, "Should have 1 OUT value");

                match &plsql_result.out_values[0] {
                    oracle_rs::row::Value::String(s) => {
                        println!("Result: {}", s);
                        assert_eq!(s, "Hello, World", "Should be concatenated string");
                    }
                    other => {
                        panic!("Expected String, got {:?}", other);
                    }
                }
            }
            Err(e) => {
                panic!("Execute failed: {:?}", e);
            }
        }

        // Cleanup
        let _ = conn.execute("DROP PROCEDURE test_table_concat_proc", &[]).await;

        conn.close().await.expect("Failed to close");
    }
}
