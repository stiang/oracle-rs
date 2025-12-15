# oracle-rs

A pure Rust driver for Oracle databases. No OCI or ODPI-C dependencies required.

[![Crates.io](https://img.shields.io/crates/v/oracle-rs.svg)](https://crates.io/crates/oracle-rs)
[![Documentation](https://docs.rs/oracle-rs/badge.svg)](https://docs.rs/oracle-rs)
[![License](https://img.shields.io/crates/l/oracle-rs.svg)](LICENSE-APACHE)

## Features

- **Pure Rust** - No Oracle client libraries required
- **Async/await** - Built on Tokio for modern async applications
- **TLS/SSL** - Secure connections with certificate and wallet support
- **Connection Pooling** - Via the companion `deadpool-oracle` crate
- **Statement Caching** - LRU cache for prepared statements
- **Comprehensive Type Support** - Including LOBs, JSON, VECTORs, and more

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
oracle-rs = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Basic usage:

```rust
use oracle_rs::{Config, Connection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Oracle
    let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
    let conn = Connection::connect_with_config(config).await?;

    // Execute a query
    let result = conn.query("SELECT id, name FROM users WHERE active = :1", &[&1]).await?;

    for row in result.rows() {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        println!("User {}: {}", id, name);
    }

    Ok(())
}
```

## Connection Options

### Basic Connection

```rust
use oracle_rs::{Config, Connection};

let config = Config::new("hostname", 1521, "service_name", "username", "password");
let conn = Connection::connect_with_config(config).await?;
```

### TLS/SSL Connection

```rust
use oracle_rs::Config;

let config = Config::new("hostname", 2484, "service_name", "username", "password")
    .with_tls()?;  // Use system root certificates

let conn = Connection::connect_with_config(config).await?;
```

### Oracle Wallet (ewallet.pem)

```rust
use oracle_rs::Config;

let config = Config::new("hostname", 2484, "service_name", "username", "password")
    .with_wallet("/path/to/wallet", Some("wallet_password"))?;

let conn = Connection::connect_with_config(config).await?;
```

### Database Resident Connection Pooling (DRCP)

```rust
use oracle_rs::Config;

let config = Config::new("hostname", 1521, "service_name", "username", "password")
    .with_drcp("connection_class", "purity");
```

### Statement Caching

```rust
use oracle_rs::Config;

let config = Config::new("hostname", 1521, "service_name", "username", "password")
    .with_statement_cache_size(100);  // Cache up to 100 statements
```

## Query Execution

### SELECT Queries

```rust
// Simple query
let result = conn.query("SELECT * FROM employees", &[]).await?;

// With bind parameters
let result = conn.query(
    "SELECT * FROM employees WHERE department_id = :1 AND salary > :2",
    &[&10, &50000.0]
).await?;

// Access rows
for row in result.rows() {
    let name: String = row.get("employee_name")?;
    let salary: f64 = row.get("salary")?;
}
```

### DML Operations

```rust
// INSERT
let result = conn.execute(
    "INSERT INTO users (id, name) VALUES (:1, :2)",
    &[&1, &"Alice"]
).await?;
println!("Rows inserted: {}", result.rows_affected);

// UPDATE
let result = conn.execute(
    "UPDATE users SET name = :1 WHERE id = :2",
    &[&"Bob", &1]
).await?;

// DELETE
let result = conn.execute(
    "DELETE FROM users WHERE id = :1",
    &[&1]
).await?;
```

### Batch Operations

```rust
use oracle_rs::BatchBuilder;

let batch = BatchBuilder::new("INSERT INTO users (id, name) VALUES (:1, :2)")
    .add_row(&[&1, &"Alice"])?
    .add_row(&[&2, &"Bob"])?
    .add_row(&[&3, &"Charlie"])?;

let result = conn.execute_batch(batch).await?;
```

### Transactions

```rust
// Auto-commit is off by default
conn.execute("INSERT INTO accounts (id, balance) VALUES (:1, :2)", &[&1, &100.0]).await?;
conn.execute("UPDATE accounts SET balance = balance - :1 WHERE id = :2", &[&50.0, &1]).await?;

// Commit the transaction
conn.commit().await?;

// Or rollback on error
conn.rollback().await?;

// Savepoints
conn.savepoint("before_update").await?;
conn.execute("UPDATE accounts SET balance = 0 WHERE id = :1", &[&1]).await?;
conn.rollback_to_savepoint("before_update").await?;  // Undo the update
```

## PL/SQL

### Anonymous Blocks

```rust
conn.execute(
    "BEGIN
        UPDATE accounts SET balance = balance + :1 WHERE id = :2;
        UPDATE accounts SET balance = balance - :1 WHERE id = :3;
     END;",
    &[&100.0, &1, &2]
).await?;
```

### OUT Parameters

```rust
use oracle_rs::{Value, OracleType};

let mut out_value = Value::null(OracleType::Number);

conn.execute_with_binds(
    "BEGIN :result := calculate_tax(:amount); END;",
    &mut [
        ("result", &mut out_value, BindDirection::Out),
        ("amount", &mut Value::from(1000.0), BindDirection::In),
    ]
).await?;

let tax: f64 = out_value.try_into()?;
```

### REF CURSOR

```rust
let mut cursor = Value::null(OracleType::Cursor);

conn.execute_with_binds(
    "BEGIN OPEN :cursor FOR SELECT * FROM employees WHERE dept_id = :dept; END;",
    &mut [
        ("cursor", &mut cursor, BindDirection::Out),
        ("dept", &mut Value::from(10), BindDirection::In),
    ]
).await?;

// Fetch from the cursor
let result = conn.fetch_ref_cursor(&cursor, 100).await?;
for row in result.rows() {
    // Process rows
}
```

## Data Types

### Supported Types

| Oracle Type | Rust Type |
|-------------|-----------|
| NUMBER | `i8`, `i16`, `i32`, `i64`, `f32`, `f64`, `String` |
| VARCHAR2, CHAR | `String`, `&str` |
| DATE | `chrono::NaiveDateTime` |
| TIMESTAMP | `chrono::NaiveDateTime` |
| TIMESTAMP WITH TIME ZONE | `chrono::DateTime<FixedOffset>` |
| INTERVAL DAY TO SECOND | `chrono::Duration` |
| RAW | `Vec<u8>`, `&[u8]` |
| CLOB, NCLOB | `String` (auto-fetched) or streaming |
| BLOB | `Vec<u8>` (auto-fetched) or streaming |
| BOOLEAN | `bool` |
| JSON | `serde_json::Value` |
| VECTOR | `Vec<f32>`, `Vec<f64>`, `Vec<i8>` |
| ROWID | `String` |
| BINARY_FLOAT | `f32` |
| BINARY_DOUBLE | `f64` |

### Working with LOBs

```rust
// Small LOBs are auto-fetched as String/Vec<u8>
let result = conn.query("SELECT document FROM files WHERE id = :1", &[&1]).await?;
let content: String = result.rows()[0].get("document")?;

// Large LOB streaming
let lob = conn.get_lob("SELECT document FROM files WHERE id = :1", &[&1]).await?;
let mut buffer = vec![0u8; 8192];
while let Some(bytes_read) = lob.read(&mut buffer).await? {
    // Process chunk
}
```

### Working with JSON

```rust
use serde_json::json;

// Insert JSON
let data = json!({"name": "Alice", "roles": ["admin", "user"]});
conn.execute(
    "INSERT INTO documents (id, data) VALUES (:1, :2)",
    &[&1, &data]
).await?;

// Query JSON
let result = conn.query("SELECT data FROM documents WHERE id = :1", &[&1]).await?;
let data: serde_json::Value = result.rows()[0].get("data")?;
```

### Working with VECTORs (Oracle 23ai)

```rust
// Insert vector embeddings
let embedding: Vec<f32> = vec![0.1, 0.2, 0.3, /* ... */];
conn.execute(
    "INSERT INTO embeddings (id, vector) VALUES (:1, :2)",
    &[&1, &embedding]
).await?;

// Vector similarity search
let query_vector: Vec<f32> = get_embedding("search text");
let result = conn.query(
    "SELECT id, description FROM embeddings
     ORDER BY VECTOR_DISTANCE(vector, :1, COSINE)
     FETCH FIRST 10 ROWS ONLY",
    &[&query_vector]
).await?;
```

## Connection Pooling

Use the `deadpool-oracle` crate for connection pooling:

```toml
[dependencies]
oracle-rs = "0.1"
deadpool-oracle = "0.1"
```

```rust
use oracle_rs::Config;
use deadpool_oracle::PoolBuilder;

let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
let pool = PoolBuilder::new(config)
    .max_size(20)
    .build()?;

// Get a connection from the pool
let conn = pool.get().await?;

// Use the connection
let result = conn.query("SELECT * FROM users", &[]).await?;

// Connection is automatically returned to the pool when dropped
```

## Scrollable Cursors

```rust
// Create a scrollable cursor
let cursor = conn.create_scrollable_cursor(
    "SELECT * FROM large_table ORDER BY id"
).await?;

// Navigate the result set
let first = cursor.fetch_first(10).await?;      // First 10 rows
let last = cursor.fetch_last(10).await?;        // Last 10 rows
let abs = cursor.fetch_absolute(100, 10).await?; // 10 rows starting at position 100
let rel = cursor.fetch_relative(-5, 10).await?;  // 10 rows, 5 positions back from current
```

## What's Not Yet Implemented

The following features are planned but not yet available:

- **LONG/LONG RAW** - Legacy deprecated types
- **XMLType** - XML document type
- **Associative Arrays** - PL/SQL INDEX BY tables
- **Advanced Queuing (AQ)** - Oracle message queuing
- **Change Notifications (CQN)** - Push notifications on data changes
- **Sharding** - Distributed database routing
- **XA Transactions** - Two-phase commit
- **SODA** - Document/NoSQL API
- **Application Continuity** - Transparent failover

## Minimum Oracle Version

Oracle Database 12c Release 1 (12.1) or later. Some features require newer versions:

- **Native BOOLEAN**: Oracle 23c (emulated on earlier versions)
- **JSON type**: Oracle 21c (use CLOB with JSON on earlier versions)
- **VECTOR type**: Oracle 23ai

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Author

[Stian Grytøyr](https://github.com/stiang)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
