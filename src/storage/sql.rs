use sea_query::{SqliteQueryBuilder, Values};
use worker::{SqlCursor, SqlStorage, SqlStorageValue};

pub fn exec(sql: &SqlStorage, statement: &str, values: Values) -> worker::Result<SqlCursor> {
    sql.exec(statement, Some(values_to_bindings(values)))
}

pub fn exec_no_bindings(sql: &SqlStorage, statement: &str) -> worker::Result<SqlCursor> {
    sql.exec(statement, None)
}

#[allow(dead_code)]
pub fn build<Q>(query: &Q) -> (String, Values)
where
    Q: sea_query::QueryStatementBuilder,
{
    query.build_any(&SqliteQueryBuilder)
}

#[allow(dead_code)]
pub fn to_string<S>(statement: &S) -> String
where
    S: sea_query::SchemaStatementBuilder,
{
    statement.build(SqliteQueryBuilder)
}

fn values_to_bindings(values: Values) -> Vec<SqlStorageValue> {
    values.0.into_iter().map(value_to_binding).collect()
}

fn value_to_binding(value: sea_query::Value) -> SqlStorageValue {
    match value {
        sea_query::Value::Bool(v) => v.into(),
        sea_query::Value::TinyInt(v) => v.map(|v| v as i64).into(),
        sea_query::Value::SmallInt(v) => v.map(|v| v as i64).into(),
        sea_query::Value::Int(v) => v.map(|v| v as i64).into(),
        sea_query::Value::BigInt(v) => v.into(),
        sea_query::Value::TinyUnsigned(v) => v.map(|v| v as i64).into(),
        sea_query::Value::SmallUnsigned(v) => v.map(|v| v as i64).into(),
        sea_query::Value::Unsigned(v) => v.map(|v| v as i64).into(),
        sea_query::Value::BigUnsigned(v) => v.map(|v| v as i64).into(),
        sea_query::Value::Float(v) => v.map(|v| v as f64).into(),
        sea_query::Value::Double(v) => v.into(),
        sea_query::Value::String(v) => v.map(|v| *v).into(),
        sea_query::Value::Char(v) => v.map(|v| v.to_string()).into(),
        sea_query::Value::Bytes(v) => v.map(|v| *v).into(),
    }
}
