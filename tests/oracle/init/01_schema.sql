-- Schema setup for oracle-rs integration tests
-- Init scripts run as SYS on the CDB, so we must switch to the PDB
-- and create objects under the app user's schema.

ALTER SESSION SET CONTAINER = FREEPDB1;

-- Create objects as TESTUSER
-- (APP_USER is created automatically by the container entrypoint)
ALTER SESSION SET CURRENT_SCHEMA = TESTUSER;

--------------------------------------------------------
-- test_departments
--------------------------------------------------------
CREATE TABLE testuser.test_departments (
    dept_id   NUMBER PRIMARY KEY,
    dept_name VARCHAR2(100) NOT NULL
);

INSERT INTO testuser.test_departments (dept_id, dept_name) VALUES (1, 'Engineering');
INSERT INTO testuser.test_departments (dept_id, dept_name) VALUES (2, 'Marketing');
INSERT INTO testuser.test_departments (dept_id, dept_name) VALUES (3, 'Sales');
INSERT INTO testuser.test_departments (dept_id, dept_name) VALUES (4, 'HR');
INSERT INTO testuser.test_departments (dept_id, dept_name) VALUES (10, 'Operations');

--------------------------------------------------------
-- test_employees
--------------------------------------------------------
CREATE TABLE testuser.test_employees (
    emp_id     NUMBER PRIMARY KEY,
    first_name VARCHAR2(100) NOT NULL,
    last_name  VARCHAR2(100) NOT NULL,
    dept_id    NUMBER REFERENCES testuser.test_departments(dept_id),
    salary     NUMBER,
    email      VARCHAR2(200)
);

INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (1, 'John', 'Smith', 1, 75000, 'john.smith@example.com');
INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (2, 'Jane', 'Doe', 1, 82000, 'jane.doe@example.com');
INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (3, 'Bob', 'Johnson', 2, 65000, 'bob.johnson@example.com');
INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (4, 'Alice', 'Williams', 3, 90000, 'alice.williams@example.com');
INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (5, 'Charlie', 'Brown', 4, 55000, NULL);
INSERT INTO testuser.test_employees (emp_id, first_name, last_name, dept_id, salary, email)
    VALUES (10, 'Dave', 'Miller', 10, 70000, 'dave.miller@example.com');

--------------------------------------------------------
-- test_data_types
--------------------------------------------------------
CREATE TABLE testuser.test_data_types (
    id            NUMBER PRIMARY KEY,
    val_integer   NUMBER,
    val_number    NUMBER(15,2),
    val_varchar   VARCHAR2(200),
    val_date      DATE,
    val_timestamp TIMESTAMP,
    val_float     BINARY_FLOAT,
    val_double    BINARY_DOUBLE,
    val_raw       RAW(200),
    val_clob      CLOB
);

-- id=1: all columns populated
INSERT INTO testuser.test_data_types (id, val_integer, val_number, val_varchar, val_date, val_timestamp, val_float, val_double, val_raw, val_clob)
    VALUES (
        1,
        42,
        12345.67,
        'Hello Oracle',
        TO_DATE('2024-01-15', 'YYYY-MM-DD'),
        TO_TIMESTAMP('2024-01-15 10:30:00', 'YYYY-MM-DD HH24:MI:SS'),
        3.14,
        2.718281828,
        HEXTORAW('DEADBEEF'),
        'This is a CLOB text'
    );

-- id=3: only id populated, everything else NULL
INSERT INTO testuser.test_data_types (id) VALUES (3);

--------------------------------------------------------
-- Grant necessary privileges
--------------------------------------------------------
GRANT EXECUTE ON DBMS_LOB TO testuser;
GRANT CREATE TABLE TO testuser;
GRANT CREATE PROCEDURE TO testuser;
GRANT CREATE TYPE TO testuser;
GRANT CREATE SEQUENCE TO testuser;

COMMIT;
