//! Tests for statement execution components
//!
//! These tests verify the statement parsing, execute message building,
//! describe info parsing, and fetch message building.

use oracle_rs::constants::{
    exec_flags, exec_option, FunctionCode, MessageType, OracleType, PacketType, PACKET_HEADER_SIZE,
};
use oracle_rs::messages::{ExecuteMessage, ExecuteOptions, FetchMessage};
use oracle_rs::statement::{BindInfo, ColumnInfo, Statement, StatementType};
use oracle_rs::Capabilities;

mod statement_parsing_tests {
    use super::*;

    #[test]
    fn test_select_statement() {
        let stmt = Statement::new("SELECT * FROM employees");
        assert_eq!(stmt.statement_type(), StatementType::Query);
        assert!(stmt.is_query());
        assert!(!stmt.is_dml());
        assert!(!stmt.is_ddl());
        assert!(!stmt.is_plsql());
    }

    #[test]
    fn test_insert_statement() {
        let stmt = Statement::new("INSERT INTO employees (id, name) VALUES (1, 'John')");
        assert_eq!(stmt.statement_type(), StatementType::Dml);
        assert!(stmt.is_dml());
        assert!(!stmt.is_query());
    }

    #[test]
    fn test_update_statement() {
        let stmt = Statement::new("UPDATE employees SET name = 'Jane' WHERE id = 1");
        assert_eq!(stmt.statement_type(), StatementType::Dml);
        assert!(stmt.is_dml());
    }

    #[test]
    fn test_delete_statement() {
        let stmt = Statement::new("DELETE FROM employees WHERE id = 1");
        assert_eq!(stmt.statement_type(), StatementType::Dml);
        assert!(stmt.is_dml());
    }

    #[test]
    fn test_merge_statement() {
        let stmt = Statement::new(
            "MERGE INTO target t USING source s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.name = s.name",
        );
        assert_eq!(stmt.statement_type(), StatementType::Dml);
        assert!(stmt.is_dml());
    }

    #[test]
    fn test_create_table_statement() {
        let stmt = Statement::new("CREATE TABLE test_table (id NUMBER PRIMARY KEY)");
        assert_eq!(stmt.statement_type(), StatementType::Ddl);
        assert!(stmt.is_ddl());
    }

    #[test]
    fn test_drop_table_statement() {
        let stmt = Statement::new("DROP TABLE test_table");
        assert_eq!(stmt.statement_type(), StatementType::Ddl);
        assert!(stmt.is_ddl());
    }

    #[test]
    fn test_alter_table_statement() {
        let stmt = Statement::new("ALTER TABLE test_table ADD (new_column VARCHAR2(100))");
        assert_eq!(stmt.statement_type(), StatementType::Ddl);
        assert!(stmt.is_ddl());
    }

    #[test]
    fn test_truncate_statement() {
        let stmt = Statement::new("TRUNCATE TABLE test_table");
        assert_eq!(stmt.statement_type(), StatementType::Ddl);
        assert!(stmt.is_ddl());
    }

    #[test]
    fn test_plsql_begin_block() {
        let stmt = Statement::new("BEGIN NULL; END;");
        assert_eq!(stmt.statement_type(), StatementType::PlSql);
        assert!(stmt.is_plsql());
    }

    #[test]
    fn test_plsql_declare_block() {
        let stmt = Statement::new("DECLARE v_num NUMBER; BEGIN v_num := 1; END;");
        assert_eq!(stmt.statement_type(), StatementType::PlSql);
        assert!(stmt.is_plsql());
    }

    #[test]
    fn test_plsql_call_statement() {
        let stmt = Statement::new("CALL my_procedure()");
        assert_eq!(stmt.statement_type(), StatementType::PlSql);
        assert!(stmt.is_plsql());
    }

    #[test]
    fn test_cte_with_select() {
        let stmt =
            Statement::new("WITH cte AS (SELECT 1 x FROM dual) SELECT * FROM cte WHERE x = 1");
        assert_eq!(stmt.statement_type(), StatementType::Query);
        assert!(stmt.is_query());
    }

    #[test]
    fn test_case_insensitive_keywords() {
        assert!(Statement::new("select * from dual").is_query());
        assert!(Statement::new("SELECT * FROM dual").is_query());
        assert!(Statement::new("Select * From dual").is_query());
        assert!(Statement::new("insert into t values (1)").is_dml());
        assert!(Statement::new("INSERT INTO t VALUES (1)").is_dml());
    }
}

mod bind_variable_tests {
    use super::*;

    #[test]
    fn test_named_bind_variables() {
        let stmt = Statement::new("SELECT * FROM emp WHERE dept_id = :dept AND name = :name");
        assert_eq!(stmt.bind_info().len(), 2);
        assert_eq!(stmt.bind_info()[0].name, "DEPT");
        assert_eq!(stmt.bind_info()[1].name, "NAME");
    }

    #[test]
    fn test_positional_bind_variables() {
        let stmt = Statement::new("SELECT * FROM emp WHERE id = :1 AND status = :2");
        assert_eq!(stmt.bind_info().len(), 2);
        assert_eq!(stmt.bind_info()[0].name, "1");
        assert_eq!(stmt.bind_info()[1].name, "2");
    }

    #[test]
    fn test_quoted_bind_variables() {
        let stmt = Statement::new("SELECT * FROM emp WHERE name = :\"My Name\"");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "My Name");
    }

    #[test]
    fn test_bind_in_string_literal_ignored() {
        let stmt = Statement::new("SELECT ':not_a_bind' FROM dual WHERE x = :actual_bind");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "ACTUAL_BIND");
    }

    #[test]
    fn test_bind_in_single_line_comment_ignored() {
        let stmt = Statement::new("SELECT * FROM emp WHERE x = :x -- AND y = :y");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "X");
    }

    #[test]
    fn test_bind_in_block_comment_ignored() {
        let stmt = Statement::new("SELECT * FROM emp WHERE x = :x /* AND y = :y */");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "X");
    }

    #[test]
    fn test_duplicate_binds_in_sql() {
        // SQL allows duplicate bind positions (each is a separate placeholder)
        let stmt = Statement::new("SELECT * FROM emp WHERE x = :val OR y = :val");
        assert_eq!(stmt.bind_info().len(), 2);
    }

    #[test]
    fn test_duplicate_binds_in_plsql_deduplicated() {
        // PL/SQL deduplicates bind names
        let stmt = Statement::new("BEGIN :x := :x + 1; END;");
        assert_eq!(stmt.bind_info().len(), 1);
        assert_eq!(stmt.bind_info()[0].name, "X");
    }

    #[test]
    fn test_returning_into_binds() {
        let stmt = Statement::new(
            "INSERT INTO emp (id, name) VALUES (:id, :name) RETURNING emp_id INTO :out_id",
        );
        assert_eq!(stmt.bind_info().len(), 3);
        assert!(!stmt.bind_info()[0].is_return_bind);
        assert!(!stmt.bind_info()[1].is_return_bind);
        assert!(stmt.bind_info()[2].is_return_bind);
        assert!(stmt.is_returning());
    }

    #[test]
    fn test_update_returning_into() {
        let stmt =
            Statement::new("UPDATE emp SET name = :name WHERE id = :id RETURNING version INTO :v");
        assert!(stmt.is_returning());
        assert_eq!(stmt.bind_info().len(), 3);
        assert!(stmt.bind_info()[2].is_return_bind);
    }

    #[test]
    fn test_no_binds_in_ddl() {
        // DDL doesn't support bind variables
        let stmt = Statement::new("CREATE TABLE test_:name (id NUMBER)");
        assert_eq!(stmt.bind_info().len(), 0);
    }

    #[test]
    fn test_complex_bind_names() {
        let stmt = Statement::new("SELECT * FROM t WHERE a = :var_1 AND b = :VAR_2 AND c = :var$3");
        assert_eq!(stmt.bind_info().len(), 3);
        assert_eq!(stmt.bind_info()[0].name, "VAR_1");
        assert_eq!(stmt.bind_info()[1].name, "VAR_2");
        assert_eq!(stmt.bind_info()[2].name, "VAR$3");
    }
}

mod execute_message_tests {
    use super::*;

    #[test]
    fn test_execute_message_for_query() {
        let stmt = Statement::new("SELECT * FROM dual");
        let opts = ExecuteOptions::for_query(100);
        let msg = ExecuteMessage::new(&stmt, opts);

        assert_eq!(msg.function_code(), FunctionCode::Execute);
    }

    #[test]
    fn test_execute_message_for_dml() {
        let stmt = Statement::new("INSERT INTO t VALUES (1)");
        let opts = ExecuteOptions::for_dml(false);
        let msg = ExecuteMessage::new(&stmt, opts);

        assert_eq!(msg.function_code(), FunctionCode::Execute);
    }

    #[test]
    fn test_execute_message_builds_packet() {
        let stmt = Statement::new("SELECT 1 FROM dual");
        let opts = ExecuteOptions::for_query(100);
        let msg = ExecuteMessage::new(&stmt, opts);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Verify packet structure
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Data flags (2 bytes after header)
        let data_flags_offset = PACKET_HEADER_SIZE;
        assert_eq!(packet[data_flags_offset], 0);
        assert_eq!(packet[data_flags_offset + 1], 0);

        // Message type
        let msg_type_offset = data_flags_offset + 2;
        assert_eq!(packet[msg_type_offset], MessageType::Function as u8);

        // Function code
        assert_eq!(packet[msg_type_offset + 1], FunctionCode::Execute as u8);
    }

    #[test]
    fn test_execute_options_for_query() {
        let opts = ExecuteOptions::for_query(50);
        assert!(opts.parse);
        assert!(opts.execute);
        assert!(opts.fetch);
        assert_eq!(opts.prefetch_rows, 50);
        assert!(!opts.commit);
    }

    #[test]
    fn test_execute_options_for_dml_with_commit() {
        let opts = ExecuteOptions::for_dml(true);
        assert!(opts.parse);
        assert!(opts.execute);
        assert!(opts.commit);
        assert!(!opts.fetch);
    }

    #[test]
    fn test_execute_options_for_plsql() {
        let opts = ExecuteOptions::for_plsql();
        assert!(opts.parse);
        assert!(opts.execute);
        assert!(!opts.commit);
        assert!(!opts.fetch);
    }

    #[test]
    fn test_execute_options_describe_only() {
        let opts = ExecuteOptions::describe_only();
        assert!(opts.parse);
        assert!(opts.describe_only);
        assert!(!opts.execute);
    }
}

mod fetch_message_tests {
    use super::*;

    #[test]
    fn test_fetch_message_creation() {
        let msg = FetchMessage::new(42, 100);
        assert_eq!(msg.cursor_id(), 42);
        assert_eq!(msg.num_rows(), 100);
    }

    #[test]
    fn test_fetch_message_builds_packet() {
        let msg = FetchMessage::new(1, 50);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Verify packet structure
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Check message structure
        let msg_offset = PACKET_HEADER_SIZE + 2; // Skip data flags
        assert_eq!(packet[msg_offset], MessageType::Function as u8);
        assert_eq!(packet[msg_offset + 1], FunctionCode::Fetch as u8);
    }

    #[test]
    fn test_fetch_zero_rows() {
        let msg = FetchMessage::new(1, 0);
        let caps = Capabilities::new();

        // Should still build successfully (server will return no rows)
        let packet = msg.build_request(&caps).unwrap();
        assert!(packet.len() > PACKET_HEADER_SIZE);
    }

    #[test]
    fn test_fetch_large_row_count() {
        let msg = FetchMessage::new(1, 10000);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();
        assert!(packet.len() > PACKET_HEADER_SIZE);
    }
}

mod oracle_type_tests {
    use super::*;

    #[test]
    fn test_oracle_type_from_u8() {
        assert_eq!(OracleType::try_from(1u8).unwrap(), OracleType::Varchar);
        assert_eq!(OracleType::try_from(2u8).unwrap(), OracleType::Number);
        assert_eq!(OracleType::try_from(12u8).unwrap(), OracleType::Date);
        assert_eq!(OracleType::try_from(96u8).unwrap(), OracleType::Char);
        assert_eq!(OracleType::try_from(100u8).unwrap(), OracleType::BinaryFloat);
        assert_eq!(
            OracleType::try_from(101u8).unwrap(),
            OracleType::BinaryDouble
        );
        assert_eq!(OracleType::try_from(112u8).unwrap(), OracleType::Clob);
        assert_eq!(OracleType::try_from(113u8).unwrap(), OracleType::Blob);
        assert_eq!(OracleType::try_from(180u8).unwrap(), OracleType::Timestamp);
        assert_eq!(
            OracleType::try_from(181u8).unwrap(),
            OracleType::TimestampTz
        );
        assert_eq!(OracleType::try_from(252u8).unwrap(), OracleType::Boolean);
    }

    #[test]
    fn test_oracle_type_invalid() {
        assert!(OracleType::try_from(0u8).is_err());
        assert!(OracleType::try_from(255u8).is_err());
        assert!(OracleType::try_from(99u8).is_err());
    }

    #[test]
    fn test_oracle_type_repr() {
        assert_eq!(OracleType::Varchar as u8, 1);
        assert_eq!(OracleType::Number as u8, 2);
        assert_eq!(OracleType::Date as u8, 12);
    }
}

mod column_info_tests {
    use super::*;

    #[test]
    fn test_column_info_creation() {
        let col = ColumnInfo::new("EMPLOYEE_ID", OracleType::Number);
        assert_eq!(col.name, "EMPLOYEE_ID");
        assert_eq!(col.oracle_type, OracleType::Number);
        assert!(col.nullable);
    }

    #[test]
    fn test_bind_info_creation() {
        let bind = BindInfo::new("param1", false);
        assert_eq!(bind.name, "param1");
        assert!(!bind.is_return_bind);
    }

    #[test]
    fn test_bind_info_return_bind() {
        let bind = BindInfo::new("out_id", true);
        assert_eq!(bind.name, "out_id");
        assert!(bind.is_return_bind);
    }
}

mod statement_state_tests {
    use super::*;

    #[test]
    fn test_statement_initial_state() {
        let stmt = Statement::new("SELECT 1 FROM dual");
        assert_eq!(stmt.cursor_id(), 0);
        assert!(!stmt.executed());
        assert!(!stmt.binds_changed());
        assert!(!stmt.requires_define());
    }

    #[test]
    fn test_statement_cursor_id() {
        let mut stmt = Statement::new("SELECT 1 FROM dual");
        stmt.set_cursor_id(42);
        assert_eq!(stmt.cursor_id(), 42);
    }

    #[test]
    fn test_statement_executed_flag() {
        let mut stmt = Statement::new("SELECT 1 FROM dual");
        stmt.set_executed(true);
        assert!(stmt.executed());
    }

    #[test]
    fn test_statement_clear() {
        let mut stmt = Statement::new("SELECT 1 FROM dual");
        stmt.set_cursor_id(42);
        stmt.set_executed(true);
        stmt.set_binds_changed(true);

        stmt.clear();

        assert_eq!(stmt.cursor_id(), 0);
        assert!(!stmt.executed());
        assert!(!stmt.binds_changed());
    }

    #[test]
    fn test_statement_columns() {
        let mut stmt = Statement::new("SELECT id, name FROM dual");
        assert_eq!(stmt.column_count(), 0);

        let columns = vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ];
        stmt.set_columns(columns);

        assert_eq!(stmt.column_count(), 2);
        assert_eq!(stmt.columns()[0].name, "ID");
        assert_eq!(stmt.columns()[1].name, "NAME");
    }
}

mod integration_tests {
    use super::*;

    #[test]
    fn test_complete_query_workflow() {
        // 1. Create statement
        let mut stmt = Statement::new("SELECT id, name FROM employees WHERE dept_id = :dept");
        assert!(stmt.is_query());
        assert_eq!(stmt.bind_info().len(), 1);

        // 2. Build execute message (first execution)
        let opts = ExecuteOptions::for_query(100);
        let msg = ExecuteMessage::new(&stmt, opts);
        let caps = Capabilities::new();
        let packet = msg.build_request(&caps).unwrap();
        assert!(!packet.is_empty());

        // 3. After server responds, we'd have a cursor ID and column metadata
        stmt.set_cursor_id(1);
        stmt.set_executed(true);
        stmt.set_columns(vec![
            ColumnInfo::new("ID", OracleType::Number),
            ColumnInfo::new("NAME", OracleType::Varchar),
        ]);

        // 4. Fetch more rows
        let fetch = FetchMessage::new(stmt.cursor_id(), 100);
        let fetch_packet = fetch.build_request(&caps).unwrap();
        assert!(!fetch_packet.is_empty());
    }

    #[test]
    fn test_complete_dml_workflow() {
        // 1. Create statement
        let stmt = Statement::new("INSERT INTO employees (id, name) VALUES (:id, :name)");
        assert!(stmt.is_dml());
        assert_eq!(stmt.bind_info().len(), 2);

        // 2. Build execute message with commit
        let opts = ExecuteOptions::for_dml(true);
        let msg = ExecuteMessage::new(&stmt, opts);
        let caps = Capabilities::new();
        let packet = msg.build_request(&caps).unwrap();
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_complete_plsql_workflow() {
        // 1. Create PL/SQL block with bind variables
        let stmt = Statement::new("BEGIN :result := my_function(:input); END;");
        assert!(stmt.is_plsql());
        assert_eq!(stmt.bind_info().len(), 2);

        // 2. Build execute message
        let opts = ExecuteOptions::for_plsql();
        let msg = ExecuteMessage::new(&stmt, opts);
        let caps = Capabilities::new();
        let packet = msg.build_request(&caps).unwrap();
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_describe_only_workflow() {
        // Use describe_only to get column metadata without executing
        let stmt = Statement::new("SELECT * FROM large_table");
        let opts = ExecuteOptions::describe_only();
        let msg = ExecuteMessage::new(&stmt, opts);

        // This should use Execute function code (not ReexecuteAndFetch)
        assert_eq!(msg.function_code(), FunctionCode::Execute);
    }
}
