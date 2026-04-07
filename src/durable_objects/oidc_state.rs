use sea_query::{Alias, ColumnDef, Expr, Query, SqliteQueryBuilder, Table};
use worker::*;

use crate::{
    do_protocol::{OidcStateRecord, OidcStateRequest},
    storage::sql::{exec, exec_no_bindings},
};

#[durable_object(alarm)]
pub struct OidcStateObject {
    state: State,
    env: Env,
}

impl DurableObject for OidcStateObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let _ = &self.env;
        self.init()?;
        let request: OidcStateRequest = req.json().await?;
        match request {
            OidcStateRequest::Store(record) => {
                self.store(record).await?;
                Response::from_json(&true)
            }
            OidcStateRequest::Consume { state, now } => {
                let record = self.consume(&state, now).await?;
                Response::from_json(&record)
            }
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        Response::empty()
    }
}

impl OidcStateObject {
    fn init(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut table = Table::create();
        table
            .table(Alias::new("oidc_state"))
            .if_not_exists()
            .col(
                ColumnDef::new(Alias::new("state"))
                    .string()
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(Alias::new("host")).string().not_null())
            .col(
                ColumnDef::new(Alias::new("code_verifier"))
                    .string()
                    .not_null(),
            )
            .col(ColumnDef::new(Alias::new("nonce")).string().not_null())
            .col(
                ColumnDef::new(Alias::new("created_at"))
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(Alias::new("expires_at"))
                    .big_integer()
                    .not_null(),
            );
        exec_no_bindings(&sql, &table.to_string(SqliteQueryBuilder))?;
        Ok(())
    }

    async fn store(&self, record: OidcStateRecord) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut delete = Query::delete();
        delete
            .from_table(Alias::new("oidc_state"))
            .and_where(Expr::col(Alias::new("state")).eq(record.state.clone()));
        let (statement, values) = delete.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;

        let mut insert = Query::insert();
        insert
            .into_table(Alias::new("oidc_state"))
            .columns([
                Alias::new("state"),
                Alias::new("host"),
                Alias::new("code_verifier"),
                Alias::new("nonce"),
                Alias::new("created_at"),
                Alias::new("expires_at"),
            ])
            .values_panic([
                record.state.into(),
                record.host.into(),
                record.code_verifier.into(),
                record.nonce.into(),
                record.created_at.into(),
                record.expires_at.into(),
            ]);
        let (statement, values) = insert.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        let ttl_ms = (record.expires_at - record.created_at).max(1) * 1000;
        self.state.storage().set_alarm(ttl_ms).await?;
        Ok(())
    }

    async fn consume(&self, state: &str, now: i64) -> Result<Option<OidcStateRecord>> {
        let sql = self.state.storage().sql();
        let mut select = Query::select();
        select
            .columns([
                Alias::new("state"),
                Alias::new("host"),
                Alias::new("code_verifier"),
                Alias::new("nonce"),
                Alias::new("created_at"),
                Alias::new("expires_at"),
            ])
            .from(Alias::new("oidc_state"))
            .and_where(Expr::col(Alias::new("state")).eq(state.to_string()));
        let (statement, values) = select.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        let record = cursor
            .raw()
            .next()
            .transpose()?
            .and_then(record_from_row)
            .filter(|record| record.expires_at >= now);

        let mut delete = Query::delete();
        delete
            .from_table(Alias::new("oidc_state"))
            .and_where(Expr::col(Alias::new("state")).eq(state.to_string()));
        let (statement, values) = delete.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        self.state.storage().delete_all().await?;
        Ok(record)
    }
}

fn record_from_row(row: Vec<worker::SqlStorageValue>) -> Option<OidcStateRecord> {
    Some(OidcStateRecord {
        state: string_at(&row, 0)?,
        host: string_at(&row, 1)?,
        code_verifier: string_at(&row, 2)?,
        nonce: string_at(&row, 3)?,
        created_at: int_at(&row, 4)?,
        expires_at: int_at(&row, 5)?,
    })
}

fn string_at(row: &[worker::SqlStorageValue], index: usize) -> Option<String> {
    match row.get(index)? {
        worker::SqlStorageValue::String(v) => Some(v.clone()),
        _ => None,
    }
}

fn int_at(row: &[worker::SqlStorageValue], index: usize) -> Option<i64> {
    match row.get(index)? {
        worker::SqlStorageValue::Integer(v) => Some(*v),
        _ => None,
    }
}
