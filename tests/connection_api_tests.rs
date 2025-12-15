//! Integration tests for the Connection API
//!
//! These tests verify the Connection API structure and behavior.
//! Note: These are unit/API tests that don't require a real Oracle database.

use oracle_rs::{
    ColumnInfo, Config, ConnectionState, Error, QueryOptions, QueryResult, Row, ServerInfo, Value,
};
use oracle_rs::constants::OracleType;

mod config_tests {
    use super::*;

    #[test]
    fn test_config_from_connection_string() {
        let config: Config = "localhost:1521/ORCLPDB1".parse().unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 1521);
    }

    #[test]
    fn test_config_with_credentials() {
        let mut config: Config = "localhost/ORCLPDB1".parse().unwrap();
        config.set_username("scott");
        config.set_password("tiger");
        assert_eq!(config.username, "scott");
    }

    #[test]
    fn test_config_default_port() {
        let config: Config = "localhost/ORCLPDB1".parse().unwrap();
        assert_eq!(config.port, 1521);
    }
}

mod query_result_tests {
    use super::*;

    #[test]
    fn test_empty_query_result() {
        let result = QueryResult::empty();
        assert!(result.is_empty());
        assert_eq!(result.column_count(), 0);
        assert_eq!(result.row_count(), 0);
        assert!(result.first().is_none());
        assert!(!result.has_more_rows);
    }

    #[test]
    fn test_query_result_with_columns_and_rows() {
        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ];

        let rows = vec![
            Row::new(vec![Value::Integer(1), Value::String("Alice".to_string())]),
            Row::new(vec![Value::Integer(2), Value::String("Bob".to_string())]),
        ];

        let result = QueryResult {
            columns,
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 1,
        };

        assert!(!result.is_empty());
        assert_eq!(result.column_count(), 2);
        assert_eq!(result.row_count(), 2);
        assert!(result.first().is_some());
    }

    #[test]
    fn test_query_result_column_lookup() {
        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
            ColumnInfo::new("EMAIL", OracleType::Varchar),
        ];

        let result = QueryResult {
            columns,
            rows: vec![],
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        // Case-insensitive lookup
        assert!(result.column_by_name("ID").is_some());
        assert!(result.column_by_name("id").is_some());
        assert!(result.column_by_name("Id").is_some());

        // Column index lookup
        assert_eq!(result.column_index("NAME"), Some(1));
        assert_eq!(result.column_index("name"), Some(1));
        assert_eq!(result.column_index("NONEXISTENT"), None);
    }

    #[test]
    fn test_query_result_iteration() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
            Row::new(vec![Value::Integer(3)]),
        ];

        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        // Test iter()
        let collected: Vec<_> = result.iter().collect();
        assert_eq!(collected.len(), 3);

        // Test into_iter()
        let collected: Vec<Row> = result.into_iter().collect();
        assert_eq!(collected.len(), 3);
    }
}

mod query_options_tests {
    use super::*;

    #[test]
    fn test_default_query_options() {
        let opts = QueryOptions::default();
        assert_eq!(opts.prefetch_rows, 100);
        assert_eq!(opts.array_size, 100);
        assert!(!opts.auto_commit);
    }

    #[test]
    fn test_custom_query_options() {
        let opts = QueryOptions {
            prefetch_rows: 500,
            array_size: 200,
            auto_commit: true,
        };
        assert_eq!(opts.prefetch_rows, 500);
        assert!(opts.auto_commit);
    }
}

mod server_info_tests {
    use super::*;

    #[test]
    fn test_default_server_info() {
        let info = ServerInfo::default();
        assert!(info.version.is_empty());
        assert!(info.banner.is_empty());
        assert_eq!(info.session_id, 0);
        assert_eq!(info.serial_number, 0);
        assert!(info.instance_name.is_none());
        assert!(info.service_name.is_none());
        assert!(info.database_name.is_none());
    }
}

mod connection_state_tests {
    use super::*;

    #[test]
    fn test_connection_states() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Ready);
        assert_ne!(ConnectionState::Ready, ConnectionState::Closed);
    }
}

mod row_tests {
    use super::*;

    #[test]
    fn test_row_value_access() {
        let row = Row::new(vec![
            Value::Integer(42),
            Value::String("test".to_string()),
            Value::Null,
        ]);

        assert_eq!(row.len(), 3);
        assert!(!row.is_empty());
    }

    #[test]
    fn test_row_with_column_names() {
        let row = Row::with_names(
            vec![Value::Integer(1), Value::String("Alice".to_string())],
            vec!["ID".to_string(), "NAME".to_string()],
        );

        // Value access by name
        assert!(row.get_by_name("ID").is_some());
        assert!(row.get_by_name("NAME").is_some());
        assert!(row.get_by_name("NONEXISTENT").is_none());
    }

    #[test]
    fn test_row_index_access() {
        let row = Row::new(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]);

        // Access via index trait
        let val = &row[0];
        assert!(matches!(val, Value::Integer(1)));

        let val = &row[2];
        assert!(matches!(val, Value::Integer(3)));
    }
}

mod value_tests {
    use super::*;

    #[test]
    fn test_value_types() {
        let null = Value::Null;
        let string = Value::String("hello".to_string());
        let integer = Value::Integer(42);
        let float = Value::Float(3.14);
        let boolean = Value::Boolean(true);
        let bytes = Value::Bytes(vec![1, 2, 3]);

        assert!(matches!(null, Value::Null));
        assert!(matches!(string, Value::String(_)));
        assert!(matches!(integer, Value::Integer(42)));
        assert!(matches!(float, Value::Float(_)));
        assert!(matches!(boolean, Value::Boolean(true)));
        assert!(matches!(bytes, Value::Bytes(_)));
    }

    #[test]
    fn test_value_display() {
        assert_eq!(format!("{}", Value::Null), "NULL");
        assert_eq!(format!("{}", Value::String("test".to_string())), "test");
        assert_eq!(format!("{}", Value::Integer(42)), "42");
        assert_eq!(format!("{}", Value::Boolean(true)), "true");
    }

    #[test]
    fn test_value_is_null() {
        assert!(Value::Null.is_null());
        assert!(!Value::Integer(0).is_null());
        assert!(!Value::String("".to_string()).is_null());
    }
}

mod error_tests {
    use super::*;

    #[test]
    fn test_oracle_error() {
        let err = Error::oracle(1017, "invalid username/password");
        let msg = err.to_string();
        assert!(msg.contains("ORA-01017"));
        assert!(msg.contains("invalid username/password"));
    }

    #[test]
    fn test_is_no_data_found() {
        assert!(Error::NoDataFound.is_no_data_found());
        assert!(Error::oracle(1403, "no data found").is_no_data_found());
        assert!(!Error::oracle(1017, "test").is_no_data_found());
    }

    #[test]
    fn test_is_connection_error() {
        assert!(Error::ConnectionClosed.is_connection_error());
        assert!(Error::ConnectionRefused {
            error_code: Some(12514),
            message: Some("test".to_string()),
        }
        .is_connection_error());
        assert!(!Error::NoDataFound.is_connection_error());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(Error::ConnectionClosed.is_recoverable());
        assert!(Error::ConnectionTimeout(std::time::Duration::from_secs(10)).is_recoverable());
        assert!(!Error::InvalidCredentials.is_recoverable());
    }
}

mod column_info_tests {
    use super::*;

    #[test]
    fn test_column_info_creation() {
        let col = ColumnInfo::new("EMPLOYEE_ID", OracleType::Number);
        assert_eq!(col.name, "EMPLOYEE_ID");
        assert_eq!(col.oracle_type, OracleType::Number);
    }

    #[test]
    fn test_column_info_with_properties() {
        let mut col = ColumnInfo::new("FULL_NAME", OracleType::Varchar);
        col.data_size = 100;
        col.precision = 0;
        col.scale = 0;
        col.nullable = true;

        assert_eq!(col.data_size, 100);
        assert!(col.nullable);
    }
}
