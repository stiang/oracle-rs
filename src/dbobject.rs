//! Oracle database object type support
//!
//! This module provides types for Oracle user-defined types (UDTs), including:
//! - Object types (CREATE TYPE)
//! - Collection types (VARRAY, nested tables)
//! - PL/SQL record types
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, DbObjectType, DbObject};
//!
//! let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "pass").await?;
//!
//! // Get a type definition
//! let obj_type = conn.get_object_type("HR.EMPLOYEE_TYPE").await?;
//!
//! // Create a new object
//! let mut obj = DbObject::new(&obj_type);
//! obj.set("FIRST_NAME", "John")?;
//! obj.set("LAST_NAME", "Doe")?;
//!
//! // Use the object in a query
//! conn.execute("INSERT INTO employees VALUES (:1)", &[&obj]).await?;
//! ```

use std::collections::HashMap;

use crate::constants::OracleType;
use crate::row::Value;

/// Collection type for Oracle collections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionType {
    /// PL/SQL index-by table
    PlsqlIndexTable,
    /// Nested table
    NestedTable,
    /// VARRAY
    Varray,
}

/// An attribute of a database object type
#[derive(Debug, Clone)]
pub struct DbObjectAttr {
    /// Attribute name
    pub name: String,
    /// Oracle data type
    pub oracle_type: OracleType,
    /// Maximum size (for strings/raw)
    pub max_size: u32,
    /// Precision (for numbers)
    pub precision: u8,
    /// Scale (for numbers)
    pub scale: i8,
    /// Whether the attribute is nullable
    pub nullable: bool,
    /// Nested object type name (for object attributes)
    pub object_type_name: Option<String>,
}

impl DbObjectAttr {
    /// Create a new attribute
    pub fn new(name: impl Into<String>, oracle_type: OracleType) -> Self {
        Self {
            name: name.into(),
            oracle_type,
            max_size: 0,
            precision: 0,
            scale: 0,
            nullable: true,
            object_type_name: None,
        }
    }

    /// Set maximum size
    pub fn with_max_size(mut self, size: u32) -> Self {
        self.max_size = size;
        self
    }

    /// Set precision and scale
    pub fn with_precision(mut self, precision: u8, scale: i8) -> Self {
        self.precision = precision;
        self.scale = scale;
        self
    }

    /// Set as not nullable
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Set nested object type
    pub fn with_object_type(mut self, type_name: impl Into<String>) -> Self {
        self.object_type_name = Some(type_name.into());
        self
    }
}

/// A database object type definition
#[derive(Debug, Clone)]
pub struct DbObjectType {
    /// Schema name
    pub schema: String,
    /// Type name
    pub name: String,
    /// Package name (for PL/SQL types)
    pub package_name: Option<String>,
    /// Whether this is a collection type
    pub is_collection: bool,
    /// Collection type (if this is a collection)
    pub collection_type: Option<CollectionType>,
    /// Element type for collections
    pub element_type: Option<OracleType>,
    /// Element type name for object collections
    pub element_type_name: Option<String>,
    /// Attributes (for object types)
    pub attributes: Vec<DbObjectAttr>,
    /// OID of the type
    pub oid: Option<Vec<u8>>,
}

impl DbObjectType {
    /// Create a new object type
    pub fn new(schema: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
            package_name: None,
            is_collection: false,
            collection_type: None,
            element_type: None,
            element_type_name: None,
            attributes: Vec::new(),
            oid: None,
        }
    }

    /// Create a collection type
    pub fn collection(
        schema: impl Into<String>,
        name: impl Into<String>,
        collection_type: CollectionType,
        element_type: OracleType,
    ) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
            package_name: None,
            is_collection: true,
            collection_type: Some(collection_type),
            element_type: Some(element_type),
            element_type_name: None,
            attributes: Vec::new(),
            oid: None,
        }
    }

    /// Get the fully qualified name
    pub fn full_name(&self) -> String {
        if let Some(ref pkg) = self.package_name {
            format!("{}.{}.{}", self.schema, pkg, self.name)
        } else {
            format!("{}.{}", self.schema, self.name)
        }
    }

    /// Add an attribute
    pub fn add_attribute(&mut self, attr: DbObjectAttr) {
        self.attributes.push(attr);
    }

    /// Get an attribute by name
    pub fn attribute(&self, name: &str) -> Option<&DbObjectAttr> {
        self.attributes.iter().find(|a| a.name.eq_ignore_ascii_case(name))
    }

    /// Get the number of attributes
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }
}

/// An instance of a database object
#[derive(Debug, Clone)]
pub struct DbObject {
    /// The object type
    pub type_name: String,
    /// Attribute values (for object types)
    pub values: HashMap<String, Value>,
    /// Element values (for collections)
    pub elements: Vec<Value>,
    /// Whether this is a collection
    pub is_collection: bool,
}

impl DbObject {
    /// Create a new object instance
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            values: HashMap::new(),
            elements: Vec::new(),
            is_collection: false,
        }
    }

    /// Create a new collection instance
    pub fn collection(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            values: HashMap::new(),
            elements: Vec::new(),
            is_collection: true,
        }
    }

    /// Set an attribute value
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.values.insert(name.into().to_uppercase(), value.into());
    }

    /// Get an attribute value
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.values.get(&name.to_uppercase())
    }

    /// Check if an attribute is set
    pub fn has(&self, name: &str) -> bool {
        self.values.contains_key(&name.to_uppercase())
    }

    /// Append an element to a collection
    pub fn append(&mut self, value: impl Into<Value>) {
        self.elements.push(value.into());
    }

    /// Get collection elements
    pub fn get_elements(&self) -> &[Value] {
        &self.elements
    }

    /// Get collection length
    pub fn len(&self) -> usize {
        if self.is_collection {
            self.elements.len()
        } else {
            self.values.len()
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        if self.is_collection {
            self.elements.is_empty()
        } else {
            self.values.is_empty()
        }
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Integer(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Boolean(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_creation() {
        let obj_type = DbObjectType::new("HR", "EMPLOYEE_TYPE");
        assert_eq!(obj_type.schema, "HR");
        assert_eq!(obj_type.name, "EMPLOYEE_TYPE");
        assert_eq!(obj_type.full_name(), "HR.EMPLOYEE_TYPE");
        assert!(!obj_type.is_collection);
    }

    #[test]
    fn test_object_type_with_attributes() {
        let mut obj_type = DbObjectType::new("HR", "EMPLOYEE_TYPE");
        obj_type.add_attribute(DbObjectAttr::new("ID", OracleType::Number));
        obj_type.add_attribute(
            DbObjectAttr::new("NAME", OracleType::Varchar).with_max_size(100),
        );

        assert_eq!(obj_type.attribute_count(), 2);
        assert!(obj_type.attribute("ID").is_some());
        assert!(obj_type.attribute("name").is_some()); // case-insensitive
    }

    #[test]
    fn test_collection_type() {
        let col_type = DbObjectType::collection(
            "HR",
            "NUMBER_LIST",
            CollectionType::Varray,
            OracleType::Number,
        );

        assert!(col_type.is_collection);
        assert_eq!(col_type.collection_type, Some(CollectionType::Varray));
        assert_eq!(col_type.element_type, Some(OracleType::Number));
    }

    #[test]
    fn test_object_instance() {
        let mut obj = DbObject::new("HR.EMPLOYEE_TYPE");
        obj.set("ID", 123i64);
        obj.set("NAME", "John Doe");

        assert_eq!(obj.len(), 2);
        assert!(obj.has("ID"));
        assert!(obj.has("name")); // case-insensitive
        assert!(!obj.has("MISSING"));

        match obj.get("ID") {
            Some(Value::Integer(v)) => assert_eq!(*v, 123),
            _ => panic!("Expected Integer"),
        }
    }

    #[test]
    fn test_collection_instance() {
        let mut col = DbObject::collection("HR.NUMBER_LIST");
        col.append(1i64);
        col.append(2i64);
        col.append(3i64);

        assert!(col.is_collection);
        assert_eq!(col.len(), 3);
        assert_eq!(col.get_elements().len(), 3);
    }

    #[test]
    fn test_attribute_builder() {
        let attr = DbObjectAttr::new("SALARY", OracleType::Number)
            .with_precision(10, 2)
            .not_null();

        assert_eq!(attr.name, "SALARY");
        assert_eq!(attr.precision, 10);
        assert_eq!(attr.scale, 2);
        assert!(!attr.nullable);
    }

    #[test]
    fn test_value_from_conversions() {
        assert!(matches!(Value::from(42i64), Value::Integer(42)));
        assert!(matches!(Value::from(3.14f64), Value::Float(_)));
        assert!(matches!(Value::from("test"), Value::String(_)));
        assert!(matches!(Value::from(true), Value::Boolean(true)));
    }
}
