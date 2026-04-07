use std::net::{IpAddr, Ipv4Addr};

use sea_query::{Alias, ColumnDef, Expr, Query, SqliteQueryBuilder, Table};
use time::OffsetDateTime;
use worker::*;

use crate::{
    do_protocol::{
        AuthenticatedSessionRequest, BackchannelLogoutRequest, BatchDeleteDeviceData,
        BatchDeleteDeviceRequest, DeleteDeviceRequest, DeleteDeviceResponse, LoginDeviceRequest,
        RefreshDeviceRequest, RefreshDeviceResponse, UpdateAliasRequest,
        UpdatePreferencesDoRequest, UserSessionRequest, UserSessionResponse,
    },
    storage::sql::{exec, exec_no_bindings},
    types::{
        CfProperties, DeleteSessionData, FieldUpdate, GetSessionData, IdleTimeout, RequestContext,
        SessionContext, SessionDeleteScope, SessionDetailData, SessionGeoLocation, SessionKind,
        SessionListItem, TorTransition, UpdateSessionData, UserPreferences,
    },
};

#[durable_object(fetch)]
pub struct UserSessionObject {
    state: State,
    env: Env,
}

impl DurableObject for UserSessionObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let _ = &self.env;
        self.init()?;
        let request: UserSessionRequest = req.json().await?;
        let response = match request {
            UserSessionRequest::Login(body) => self.login(body)?,
            UserSessionRequest::Refresh(body) => self.refresh(body).await?,
            UserSessionRequest::GetSession(body) => self.get_session(body)?,
            UserSessionRequest::ListSessions(body) => self.list_sessions(body)?,
            UserSessionRequest::GetSessionDetail(body) => self.get_session_detail(body)?,
            UserSessionRequest::UpdateSession(body) => self.update_session(body)?,
            UserSessionRequest::DeleteSession(body) => self.delete_session(body).await?,
            UserSessionRequest::BatchDelete(body) => self.batch_delete(body).await?,
            UserSessionRequest::GetPreferences(body) => self.get_preferences(body)?,
            UserSessionRequest::UpdatePreferences(body) => self.update_preferences(body)?,
            UserSessionRequest::BackchannelLogout(body) => self.backchannel_logout(body).await?,
        };
        Response::from_json(&response)
    }
}

impl UserSessionObject {
    fn init(&self) -> Result<()> {
        let sql = self.state.storage().sql();

        let mut meta = Table::create();
        meta.table(Alias::new("meta"))
            .if_not_exists()
            .col(
                ColumnDef::new(Alias::new("key"))
                    .string()
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(Alias::new("value")).string().not_null());
        exec_no_bindings(&sql, &meta.to_string(SqliteQueryBuilder))?;

        let mut sessions = Table::create();
        sessions
            .table(Alias::new("sessions"))
            .if_not_exists()
            .col(
                ColumnDef::new(Alias::new("session_id"))
                    .string()
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(Alias::new("alias")).string())
            .col(
                ColumnDef::new(Alias::new("created_at"))
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(Alias::new("last_active_at"))
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(Alias::new("ip")).string().not_null())
            .col(ColumnDef::new(Alias::new("ua")).string().not_null())
            .col(ColumnDef::new(Alias::new("cf")).string().not_null())
            .col(ColumnDef::new(Alias::new("rt_hash")).string().not_null())
            .col(
                ColumnDef::new(Alias::new("rt_seq"))
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(Alias::new("revoked")).integer().not_null())
            .col(ColumnDef::new(Alias::new("oidc_sid")).string())
            .col(ColumnDef::new(Alias::new("id_token_hint")).string())
            .col(
                ColumnDef::new(Alias::new("last_is_tor"))
                    .integer()
                    .not_null(),
            );
        exec_no_bindings(&sql, &sessions.to_string(SqliteQueryBuilder))?;
        Ok(())
    }

    fn login(&self, body: LoginDeviceRequest) -> Result<UserSessionResponse> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.set_meta("host", &body.host)?;
        self.set_meta("sub", &body.sub)?;
        self.set_meta_json("identity", &body.identity)?;
        self.set_meta_json("protected", &body.protected)?;
        self.set_meta("protected_jws", &body.protected_jws)?;
        if self.get_meta("preferences")?.is_none() {
            self.set_meta_json("preferences", &body.default_preferences)?;
        }

        let cf_json = serde_json::to_string(&body.context.cf)?;
        let sql = self.state.storage().sql();
        self.delete_session_row(&body.session_id)?;
        let mut insert = Query::insert();
        insert
            .into_table(Alias::new("sessions"))
            .columns([
                Alias::new("session_id"),
                Alias::new("alias"),
                Alias::new("created_at"),
                Alias::new("last_active_at"),
                Alias::new("ip"),
                Alias::new("ua"),
                Alias::new("cf"),
                Alias::new("rt_hash"),
                Alias::new("rt_seq"),
                Alias::new("revoked"),
                Alias::new("oidc_sid"),
                Alias::new("id_token_hint"),
                Alias::new("last_is_tor"),
            ])
            .values_panic([
                Expr::val(body.session_id.clone()).into(),
                Expr::val(Option::<String>::None).into(),
                Expr::val(now).into(),
                Expr::val(now).into(),
                Expr::val(body.context.ip.to_string()).into(),
                Expr::val(body.user_agent).into(),
                Expr::val(cf_json).into(),
                Expr::val(body.refresh_token_hash).into(),
                Expr::val(body.refresh_token_seq).into(),
                Expr::val(0).into(),
                Expr::val(body.oidc_sid).into(),
                Expr::val(Some(body.id_token_hint)).into(),
                Expr::val(if body.context.cf.is_tor() { 1 } else { 0 }).into(),
            ]);
        let (statement, values) = insert.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        Ok(UserSessionResponse::Login {
            session_id: body.session_id,
        })
    }

    async fn refresh(&self, body: RefreshDeviceRequest) -> Result<UserSessionResponse> {
        let Some(session) = self.session_row(&body.session_id)? else {
            return Ok(UserSessionResponse::Refresh(RefreshDeviceResponse::Invalid));
        };
        if session.revoked {
            return Ok(UserSessionResponse::Refresh(RefreshDeviceResponse::Invalid));
        }
        if session.rt_hash != body.refresh_token_hash {
            self.revoke_session(&body.session_id)?;
            self.cleanup_if_empty().await?;
            return Ok(UserSessionResponse::Refresh(RefreshDeviceResponse::Reused));
        }

        let preferences = self.preferences()?;
        if let IdleTimeout::Duration { value } = preferences.idle_timeout {
            if session.last_active_at + value.whole_seconds() < body.now {
                self.revoke_session(&body.session_id)?;
                self.cleanup_if_empty().await?;
                return Ok(UserSessionResponse::Refresh(
                    RefreshDeviceResponse::IdleTimeout,
                ));
            }
        }
        if matches!(preferences.tor_transition, TorTransition::Deny)
            && session.last_is_tor != body.context.cf.is_tor()
        {
            self.revoke_session(&body.session_id)?;
            self.cleanup_if_empty().await?;
            return Ok(UserSessionResponse::Refresh(
                RefreshDeviceResponse::TorTransitionDenied,
            ));
        }

        let sql = self.state.storage().sql();
        let mut update = Query::update();
        update
            .table(Alias::new("sessions"))
            .value(Alias::new("rt_hash"), body.next_refresh_token_hash)
            .value(Alias::new("rt_seq"), body.next_refresh_token_seq)
            .value(Alias::new("last_active_at"), body.now)
            .value(Alias::new("ip"), body.context.ip.to_string())
            .value(Alias::new("ua"), body.user_agent)
            .value(Alias::new("cf"), serde_json::to_string(&body.context.cf)?)
            .value(
                Alias::new("last_is_tor"),
                if body.context.cf.is_tor() { 1 } else { 0 },
            )
            .and_where(Expr::col(Alias::new("session_id")).eq(body.session_id.clone()));
        let (statement, values) = update.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        let sub = self.get_meta("sub")?.unwrap_or_default();
        Ok(UserSessionResponse::Refresh(RefreshDeviceResponse::Ok(
            crate::do_protocol::RefreshDeviceData {
                session_id: body.session_id,
                sub,
            },
        )))
    }

    fn get_session(
        &self,
        body: crate::do_protocol::SessionIdentityRequest,
    ) -> Result<UserSessionResponse> {
        let session = self.require_active_session(&body.session_id)?;
        let data = GetSessionData {
            session_id: session.session_id,
            context: RequestContext {
                ip: session.ip,
                cf: session.cf,
            },
            identity: if body.include_identity {
                self.get_meta_json("identity")?
            } else {
                None
            },
            protected: if body.include_identity {
                self.get_meta("protected_jws")?
            } else {
                None
            },
        };
        Ok(UserSessionResponse::GetSession(data))
    }

    fn list_sessions(&self, body: AuthenticatedSessionRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.session_id)?;
        let sql = self.state.storage().sql();
        let mut select = Query::select();
        select
            .columns([
                Alias::new("session_id"),
                Alias::new("alias"),
                Alias::new("last_active_at"),
                Alias::new("ip"),
                Alias::new("ua"),
                Alias::new("cf"),
            ])
            .from(Alias::new("sessions"))
            .and_where(Expr::col(Alias::new("revoked")).eq(0))
            .order_by(Alias::new("last_active_at"), sea_query::Order::Desc);
        let (statement, values) = select.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        let mut items = Vec::new();
        for row in cursor.raw() {
            let row = row?;
            let session_id = string_at(&row, 0).unwrap_or_default();
            let cf = cf_at(&row, 5);
            items.push(SessionListItem {
                kind: if session_id == body.session_id {
                    SessionKind::Current
                } else {
                    SessionKind::Remote
                },
                session_id,
                alias: nullable_string_at(&row, 1),
                last_active_at: ts_at(&row, 2),
                ip: ip_at(&row, 3),
                ua: string_at(&row, 4).unwrap_or_default(),
                location: geo_from_cf(&cf),
            });
        }
        Ok(UserSessionResponse::ListSessions(items))
    }

    fn get_session_detail(&self, body: DeleteDeviceRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.current_session_id)?;
        let session = self.require_active_session(&body.target_session_id)?;
        let data = SessionDetailData {
            kind: if session.session_id == body.current_session_id {
                SessionKind::Current
            } else {
                SessionKind::Remote
            },
            session_id: session.session_id,
            alias: session.alias,
            created_at: ts(session.created_at),
            last_active_at: ts(session.last_active_at),
            context: SessionContext {
                ip: session.ip,
                ua: session.ua,
                cf: session.cf,
            },
        };
        Ok(UserSessionResponse::GetSessionDetail(data))
    }

    fn update_session(&self, body: UpdateAliasRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.current_session_id)?;
        self.require_active_session(&body.target_session_id)?;
        match body.alias {
            FieldUpdate::Ignore => {}
            FieldUpdate::Delete => self.set_alias(&body.target_session_id, None)?,
            FieldUpdate::Set(value) => self.set_alias(&body.target_session_id, Some(value))?,
        }
        let alias = self
            .session_row(&body.target_session_id)?
            .and_then(|s| s.alias);
        Ok(UserSessionResponse::UpdateSession(UpdateSessionData {
            session_id: body.target_session_id,
            alias,
        }))
    }

    async fn delete_session(&self, body: DeleteDeviceRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.current_session_id)?;
        let Some(target) = self.session_row(&body.target_session_id)? else {
            return Ok(UserSessionResponse::DeleteSession(
                DeleteDeviceResponse::NotFound,
            ));
        };
        let id_token_hint = target.id_token_hint;
        self.revoke_session(&body.target_session_id)?;
        self.cleanup_if_empty().await?;
        Ok(UserSessionResponse::DeleteSession(
            DeleteDeviceResponse::Ok {
                data: DeleteSessionData {
                    session_id: body.target_session_id,
                    logout: None,
                },
                id_token_hint,
            },
        ))
    }

    async fn batch_delete(&self, body: BatchDeleteDeviceRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.current_session_id)?;
        let sql = self.state.storage().sql();
        let mut update = Query::update();
        update
            .table(Alias::new("sessions"))
            .value(Alias::new("revoked"), 1)
            .and_where(Expr::col(Alias::new("revoked")).eq(0));
        if matches!(body.scope, SessionDeleteScope::Others) {
            update
                .and_where(Expr::col(Alias::new("session_id")).ne(body.current_session_id.clone()));
        }
        let (statement, values) = update.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        let count = cursor.rows_written() as u32;
        let current_id_token_hint = self
            .session_row(&body.current_session_id)?
            .and_then(|s| s.id_token_hint);
        self.cleanup_if_empty().await?;
        Ok(UserSessionResponse::BatchDelete(BatchDeleteDeviceData {
            count,
            current_id_token_hint,
        }))
    }

    fn get_preferences(&self, body: AuthenticatedSessionRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.session_id)?;
        Ok(UserSessionResponse::Preferences(self.preferences()?))
    }

    fn update_preferences(&self, body: UpdatePreferencesDoRequest) -> Result<UserSessionResponse> {
        self.require_active_session(&body.session_id)?;
        let mut preferences = self.preferences()?;
        if let Some(idle_timeout) = body.idle_timeout {
            preferences.idle_timeout = idle_timeout;
        }
        if let Some(tor_transition) = body.tor_transition {
            preferences.tor_transition = tor_transition;
        }
        self.set_meta_json("preferences", &preferences)?;
        Ok(UserSessionResponse::Preferences(preferences))
    }

    async fn backchannel_logout(
        &self,
        body: BackchannelLogoutRequest,
    ) -> Result<UserSessionResponse> {
        let sub = self.get_meta("sub")?.unwrap_or_default();
        if sub != body.sub {
            return Ok(UserSessionResponse::BackchannelLogout { count: 0 });
        }
        let sql = self.state.storage().sql();
        let mut update = Query::update();
        update
            .table(Alias::new("sessions"))
            .value(Alias::new("revoked"), 1)
            .and_where(Expr::col(Alias::new("revoked")).eq(0));
        if let Some(sid) = body.sid {
            update.and_where(Expr::col(Alias::new("oidc_sid")).eq(sid));
        }
        let (statement, values) = update.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        let count = cursor.rows_written() as u32;
        self.cleanup_if_empty().await?;
        Ok(UserSessionResponse::BackchannelLogout { count })
    }

    fn preferences(&self) -> Result<UserPreferences> {
        self.get_meta_json("preferences")?
            .ok_or_else(|| Error::RustError("missing preferences".to_string()))
    }

    fn require_active_session(&self, session_id: &str) -> Result<SessionRow> {
        self.session_row(session_id)?
            .filter(|s| !s.revoked)
            .ok_or_else(|| Error::RustError("session not found".to_string()))
    }

    fn session_row(&self, session_id: &str) -> Result<Option<SessionRow>> {
        let sql = self.state.storage().sql();
        let mut select = Query::select();
        select
            .columns([
                Alias::new("session_id"),
                Alias::new("alias"),
                Alias::new("created_at"),
                Alias::new("last_active_at"),
                Alias::new("ip"),
                Alias::new("ua"),
                Alias::new("cf"),
                Alias::new("rt_hash"),
                Alias::new("rt_seq"),
                Alias::new("revoked"),
                Alias::new("oidc_sid"),
                Alias::new("id_token_hint"),
                Alias::new("last_is_tor"),
            ])
            .from(Alias::new("sessions"))
            .and_where(Expr::col(Alias::new("session_id")).eq(session_id.to_string()));
        let (statement, values) = select.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        Ok(cursor.raw().next().transpose()?.map(session_from_row))
    }

    fn set_alias(&self, session_id: &str, alias: Option<String>) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut update = Query::update();
        update
            .table(Alias::new("sessions"))
            .value(Alias::new("alias"), alias)
            .and_where(Expr::col(Alias::new("session_id")).eq(session_id.to_string()));
        let (statement, values) = update.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        Ok(())
    }

    fn revoke_session(&self, session_id: &str) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut update = Query::update();
        update
            .table(Alias::new("sessions"))
            .value(Alias::new("revoked"), 1)
            .and_where(Expr::col(Alias::new("session_id")).eq(session_id.to_string()));
        let (statement, values) = update.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        Ok(())
    }

    fn delete_session_row(&self, session_id: &str) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut delete = Query::delete();
        delete
            .from_table(Alias::new("sessions"))
            .and_where(Expr::col(Alias::new("session_id")).eq(session_id.to_string()));
        let (statement, values) = delete.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        Ok(())
    }

    async fn cleanup_if_empty(&self) -> Result<()> {
        if self.active_count()? == 0 {
            let sql = self.state.storage().sql();
            for table in ["sessions", "meta"] {
                let mut delete = Query::delete();
                delete.from_table(Alias::new(table));
                let (statement, values) = delete.build(SqliteQueryBuilder);
                exec(&sql, &statement, values)?;
            }
            self.state.storage().delete_all().await?;
        }
        Ok(())
    }

    fn active_count(&self) -> Result<i64> {
        let sql = self.state.storage().sql();
        let mut select = Query::select();
        select
            .expr(Expr::cust("COUNT(*)"))
            .from(Alias::new("sessions"))
            .and_where(Expr::col(Alias::new("revoked")).eq(0));
        let (statement, values) = select.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        Ok(cursor
            .raw()
            .next()
            .transpose()?
            .and_then(|row| int_at(&row, 0))
            .unwrap_or(0))
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut delete = Query::delete();
        delete
            .from_table(Alias::new("meta"))
            .and_where(Expr::col(Alias::new("key")).eq(key.to_string()));
        let (statement, values) = delete.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;

        let mut insert = Query::insert();
        insert
            .into_table(Alias::new("meta"))
            .columns([Alias::new("key"), Alias::new("value")])
            .values_panic([key.to_string().into(), value.to_string().into()]);
        let (statement, values) = insert.build(SqliteQueryBuilder);
        exec(&sql, &statement, values)?;
        Ok(())
    }

    fn set_meta_json<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.set_meta(key, &serde_json::to_string(value)?)
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let sql = self.state.storage().sql();
        let mut select = Query::select();
        select
            .column(Alias::new("value"))
            .from(Alias::new("meta"))
            .and_where(Expr::col(Alias::new("key")).eq(key.to_string()));
        let (statement, values) = select.build(SqliteQueryBuilder);
        let cursor = exec(&sql, &statement, values)?;
        Ok(cursor
            .raw()
            .next()
            .transpose()?
            .and_then(|row| string_at(&row, 0)))
    }

    fn get_meta_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        self.get_meta(key)?
            .map(|raw| serde_json::from_str(&raw).map_err(Error::from))
            .transpose()
    }
}

#[derive(Debug, Clone)]
struct SessionRow {
    session_id: String,
    alias: Option<String>,
    created_at: i64,
    last_active_at: i64,
    ip: IpAddr,
    ua: String,
    cf: CfProperties,
    rt_hash: String,
    revoked: bool,
    id_token_hint: Option<String>,
    last_is_tor: bool,
}

fn session_from_row(row: Vec<worker::SqlStorageValue>) -> SessionRow {
    SessionRow {
        session_id: string_at(&row, 0).unwrap_or_default(),
        alias: nullable_string_at(&row, 1),
        created_at: int_at(&row, 2).unwrap_or_default(),
        last_active_at: int_at(&row, 3).unwrap_or_default(),
        ip: ip_at(&row, 4),
        ua: string_at(&row, 5).unwrap_or_default(),
        cf: cf_at(&row, 6),
        rt_hash: string_at(&row, 7).unwrap_or_default(),
        revoked: int_at(&row, 9).unwrap_or_default() != 0,
        id_token_hint: nullable_string_at(&row, 11),
        last_is_tor: int_at(&row, 12).unwrap_or_default() != 0,
    }
}

fn geo_from_cf(cf: &CfProperties) -> SessionGeoLocation {
    SessionGeoLocation {
        colo: cf.colo.clone().unwrap_or_default(),
        country: cf.country.clone(),
        city: cf.city.clone(),
        continent: cf.continent.clone(),
        coordinates: cf.coordinates(),
        postal_code: cf.postal_code.clone(),
        metro_code: cf.metro_code.clone(),
        region: cf.region.clone(),
        region_code: cf.region_code.clone(),
    }
}

fn ts(value: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(value).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn ts_at(row: &[worker::SqlStorageValue], index: usize) -> OffsetDateTime {
    ts(int_at(row, index).unwrap_or_default())
}

fn ip_at(row: &[worker::SqlStorageValue], index: usize) -> IpAddr {
    string_at(row, index)
        .and_then(|raw| raw.parse::<IpAddr>().ok())
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn cf_at(row: &[worker::SqlStorageValue], index: usize) -> CfProperties {
    string_at(row, index)
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn nullable_string_at(row: &[worker::SqlStorageValue], index: usize) -> Option<String> {
    match row.get(index)? {
        worker::SqlStorageValue::Null => None,
        worker::SqlStorageValue::String(v) => Some(v.clone()),
        _ => None,
    }
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
