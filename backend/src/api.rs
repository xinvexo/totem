use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{sse::Event, IntoResponse, Json, Response, Sse},
    routing::{get, post, put},
    Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::{
    auth,
    db::{self, StoredEntry},
    static_files,
    totp::{self, EntrySpec},
    AppState,
};

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found".to_owned(),
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error".to_owned(),
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.code,
            message: self.message,
        });
        (self.status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    password: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    authenticated: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EntryInput {
    #[serde(default, alias = "otpauthUri", alias = "uri")]
    pub otpauth_uri: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub digits: Option<u8>,
    #[serde(default)]
    pub period: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct EntryView {
    pub id: i64,
    pub issuer: String,
    pub account: String,
    pub label: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
    pub code: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
struct SecretResponse {
    secret: String,
}

#[derive(Debug, Serialize)]
struct UriResponse {
    uri: String,
}

#[derive(Debug, Serialize)]
pub struct ExportFile {
    version: u8,
    #[serde(rename = "createdAt")]
    created_at: String,
    entries: Vec<ExportEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportEntry {
    pub issuer: String,
    pub account: String,
    pub label: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
}

#[derive(Debug, Deserialize)]
pub struct ImportFile {
    pub version: u8,
    #[serde(default)]
    pub entries: Vec<ExportEntry>,
}

pub fn app(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/session", get(session))
        .route("/entries", get(list_entries).post(create_entry))
        .route("/entries/{id}", put(update_entry).delete(delete_entry))
        .route("/entries/{id}/secret", get(show_secret))
        .route("/entries/{id}/uri", get(show_uri))
        .route("/entries/{id}/otpauth", get(show_uri))
        .route("/totp/stream", get(totp_stream))
        .route("/export", get(export_entries))
        .route("/import", post(import_entries))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health))
        .nest("/api", api)
        .fallback(static_files::fallback)
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "status": "ok" })),
    )
}

async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    if is_api {
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
    }
    response
}

async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let authenticated = state
        .db
        .lock()
        .ok()
        .and_then(|connection| auth::require_session(&connection, &headers).ok())
        .is_some();
    Json(SessionResponse { authenticated })
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<Response> {
    auth::require_csrf(&headers)?;
    let client = auth::client_key(&headers);
    {
        let mut limiter = state
            .login_limiter
            .lock()
            .map_err(|_| ApiError::internal("login limiter unavailable"))?;
        limiter.prune(crate::now_seconds());
        if !limiter.allow(&client, crate::now_seconds()) {
            warn!(client = %client, "login rate limit reached");
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited".to_owned(),
                message: "Too many login attempts. Try again in a minute.".to_owned(),
            });
        }
    }
    let valid = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        let Some(hash) = db::admin_password_hash(&connection)
            .map_err(|_| ApiError::internal("database query failed"))?
        else {
            return Err(ApiError::internal("administrator is not initialized"));
        };
        auth::verify_password(&payload.password, &hash)
    };
    if !valid {
        warn!(client = %client, "login failed");
        return Err(ApiError::unauthorized(
            "invalid_credentials",
            "Incorrect password",
        ));
    }
    let token = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        auth::new_session(&connection, &state.config)?
    };
    info!(client = %client, "login succeeded");
    let mut response = Json(serde_json::json!({ "authenticated": true })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth::session_cookie(&token, &state.config))
            .map_err(|_| ApiError::internal("failed to set session cookie"))?,
    );
    Ok(response)
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    auth::require_csrf(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database unavailable"))?;
    auth::delete_current_session(&connection, &headers)
        .map_err(|_| ApiError::internal("failed to end session"))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth::clear_session_cookie(&state.config))
            .map_err(|_| ApiError::internal("failed to clear session cookie"))?,
    );
    Ok(response)
}

async fn list_entries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<EntryView>>> {
    require_authenticated(&state, &headers)?;
    let entries = snapshot_entries(&state)?;
    Ok(Json(entries))
}

async fn create_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<EntryInput>,
) -> ApiResult<(StatusCode, Json<EntryView>)> {
    auth::require_csrf(&headers)?;
    require_authenticated(&state, &headers)?;
    let spec = spec_from_input(&input, None)?;
    let (ciphertext, nonce) = state
        .crypto
        .encrypt(spec.secret.as_bytes())
        .map_err(ApiError::internal)?;
    let id = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        db::insert_entry(
            &connection,
            &spec,
            &ciphertext,
            &nonce,
            crate::now_seconds(),
        )
        .map_err(|_| ApiError::internal("failed to save entry"))?
    };
    let view = snapshot_entries(&state)?
        .into_iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| ApiError::internal("saved entry could not be read"))?;
    let _ = state.events.send(());
    info!(entry_id = id, "TOTP entry created");
    Ok((StatusCode::CREATED, Json(view)))
}

async fn update_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(input): Json<EntryInput>,
) -> ApiResult<Json<EntryView>> {
    auth::require_csrf(&headers)?;
    require_authenticated(&state, &headers)?;
    let (old_record, old_secret) = load_record_and_secret(&state, id)?;
    let spec = spec_from_input(&input, Some((&old_record, &old_secret)))?;
    let secret_changed = spec.secret != old_secret;
    let encrypted = if secret_changed {
        let (ciphertext, nonce) = state
            .crypto
            .encrypt(spec.secret.as_bytes())
            .map_err(ApiError::internal)?;
        Some((ciphertext, nonce))
    } else {
        None
    };
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        let encrypted_refs = encrypted
            .as_ref()
            .map(|(ciphertext, nonce)| (ciphertext.as_slice(), nonce.as_slice()));
        let changed =
            db::update_entry(&connection, id, &spec, encrypted_refs, crate::now_seconds())
                .map_err(|_| ApiError::internal("failed to update entry"))?;
        if !changed {
            return Err(ApiError::not_found("TOTP entry not found"));
        }
    }
    let view = snapshot_entries(&state)?
        .into_iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| ApiError::internal("updated entry could not be read"))?;
    let _ = state.events.send(());
    info!(entry_id = id, "TOTP entry updated");
    Ok(Json(view))
}

async fn delete_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    auth::require_csrf(&headers)?;
    require_authenticated(&state, &headers)?;
    let deleted = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        db::delete_entry(&connection, id)
            .map_err(|_| ApiError::internal("failed to delete entry"))?
    };
    if !deleted {
        return Err(ApiError::not_found("TOTP entry not found"));
    }
    let _ = state.events.send(());
    info!(entry_id = id, "TOTP entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn show_secret(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> ApiResult<Json<SecretResponse>> {
    require_authenticated(&state, &headers)?;
    let (_, secret) = load_record_and_secret(&state, id)?;
    Ok(Json(SecretResponse { secret }))
}

async fn show_uri(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> ApiResult<Json<UriResponse>> {
    require_authenticated(&state, &headers)?;
    let (record, secret) = load_record_and_secret(&state, id)?;
    let spec = spec_from_record(&record, secret)?;
    let uri =
        totp::make_otpauth_uri(&spec).map_err(|_| ApiError::internal("failed to create URI"))?;
    Ok(Json(UriResponse { uri }))
}

async fn export_entries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    require_authenticated(&state, &headers)?;
    let records = load_records(&state)?;
    let entries = records
        .into_iter()
        .map(|record| {
            let secret = decrypt_record(&state, &record)?;
            let spec = spec_from_record(&record, secret)?;
            Ok(ExportEntry {
                issuer: spec.issuer,
                account: spec.account,
                label: spec.label,
                secret: spec.secret,
                algorithm: spec.algorithm,
                digits: spec.digits,
                period: spec.period,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let body = serde_json::to_vec(&ExportFile {
        version: 1,
        created_at: DateTime::<Utc>::from_timestamp(crate::now_seconds(), 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339(),
        entries,
    })
    .map_err(|_| ApiError::internal("failed to create export"))?;
    let mut response = Response::new(body.into());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=totem-export.json"),
    );
    Ok(response)
}

async fn import_entries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ImportFile>,
) -> ApiResult<Json<serde_json::Value>> {
    auth::require_csrf(&headers)?;
    require_authenticated(&state, &headers)?;
    if payload.version != 1 {
        return Err(ApiError::bad_request(
            "unsupported_export_version",
            "This export version is not supported",
        ));
    }
    if payload.entries.is_empty() {
        return Err(ApiError::bad_request(
            "empty_import",
            "The import contains no entries",
        ));
    }
    if payload.entries.len() > 500 {
        return Err(ApiError::bad_request(
            "import_too_large",
            "An import may contain at most 500 entries",
        ));
    }
    let mut encrypted_entries = Vec::with_capacity(payload.entries.len());
    for entry in payload.entries {
        let input = EntryInput {
            otpauth_uri: None,
            issuer: Some(entry.issuer),
            account: Some(entry.account),
            label: Some(entry.label),
            secret: Some(entry.secret),
            algorithm: Some(entry.algorithm),
            digits: Some(entry.digits),
            period: Some(entry.period),
        };
        let spec = spec_from_input(&input, None)?;
        let (ciphertext, nonce) = state
            .crypto
            .encrypt(spec.secret.as_bytes())
            .map_err(ApiError::internal)?;
        encrypted_entries.push((spec, ciphertext, nonce.to_vec()));
    }
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        db::insert_entries(&mut connection, &encrypted_entries, crate::now_seconds())
            .map_err(|_| ApiError::internal("failed to import entries"))?;
    }
    let count = encrypted_entries.len();
    let _ = state.events.send(());
    info!(count, "TOTP entries imported");
    Ok(Json(serde_json::json!({ "imported": count })))
}

async fn totp_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>> {
    require_authenticated(&state, &headers)?;
    let mut receiver = state.events.subscribe();
    let initial = snapshot_json(&state)?;
    let stream = async_stream::stream! {
        yield Ok(Event::default().data(initial));
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                event = receiver.recv() => {
                    match event {
                        Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            match snapshot_json(&state) {
                                Ok(data) => yield Ok(Event::default().data(data)),
                                Err(_) => error!("failed to build SSE state"),
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = heartbeat.tick() => {
                    yield Ok(Event::default().comment("keepalive"));
                }
            }
        }
    };
    Ok(Sse::new(stream))
}

pub async fn scheduler(state: Arc<AppState>) {
    loop {
        let mut receiver = state.events.subscribe();
        let now = crate::now_seconds() as u64;
        let periods = match state.db.lock() {
            Ok(connection) => db::entry_periods(&connection).ok(),
            Err(_) => {
                error!("database lock poisoned in TOTP scheduler");
                None
            }
        };
        let next_boundary = periods.and_then(|periods| {
            periods
                .into_iter()
                .filter(|period| *period > 0)
                .map(|period| ((now / period) + 1) * period)
                .min()
        });
        let sleep_seconds = next_boundary
            .map(|boundary| boundary.saturating_sub(now).max(1))
            .unwrap_or(30);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(sleep_seconds)) => {
                if next_boundary.is_some() {
                    let _ = state.events.send(());
                }
            }
            _ = receiver.recv() => {}
        }
    }
}

fn require_authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database unavailable"))?;
    auth::require_session(&connection, headers)
}

fn load_records(state: &AppState) -> ApiResult<Vec<StoredEntry>> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database unavailable"))?;
    db::all_entries(&connection).map_err(|_| ApiError::internal("failed to read entries"))
}

fn load_record_and_secret(state: &AppState, id: i64) -> ApiResult<(StoredEntry, String)> {
    let record = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database unavailable"))?;
        db::find_entry(&connection, id).map_err(|_| ApiError::internal("failed to read entry"))?
    }
    .ok_or_else(|| ApiError::not_found("TOTP entry not found"))?;
    let secret = decrypt_record(state, &record)?;
    Ok((record, secret))
}

fn decrypt_record(state: &AppState, record: &StoredEntry) -> ApiResult<String> {
    let plaintext = state
        .crypto
        .decrypt(&record.secret_ciphertext, &record.secret_nonce)
        .map_err(|_| ApiError::internal("failed to decrypt TOTP secret"))?;
    String::from_utf8(plaintext).map_err(|_| ApiError::internal("stored TOTP secret is invalid"))
}

fn snapshot_entries(state: &AppState) -> ApiResult<Vec<EntryView>> {
    load_records(state)?
        .into_iter()
        .map(|record| {
            let secret = decrypt_record(state, &record)?;
            let spec = spec_from_record(&record, secret)?;
            let (code, expires_at) = totp::generate_code(&spec, crate::now_seconds() as u64)
                .map_err(|_| ApiError::internal("failed to generate TOTP code"))?;
            Ok(EntryView {
                id: record.id,
                issuer: record.issuer,
                account: record.account,
                label: record.label,
                algorithm: record.algorithm,
                digits: record.digits,
                period: record.period,
                code,
                expires_at,
                created_at: timestamp_string(record.created_at),
                updated_at: timestamp_string(record.updated_at),
            })
        })
        .collect()
}

fn snapshot_json(state: &AppState) -> ApiResult<String> {
    serde_json::to_string(&serde_json::json!({
        "type": "totp",
        "entries": snapshot_entries(state)?,
    }))
    .map_err(|_| ApiError::internal("failed to serialize TOTP state"))
}

fn spec_from_record(record: &StoredEntry, secret: String) -> ApiResult<EntrySpec> {
    Ok(EntrySpec {
        issuer: record.issuer.clone(),
        account: record.account.clone(),
        label: record.label.clone(),
        secret: totp::normalize_secret(&secret)
            .map_err(|_| ApiError::internal("stored TOTP secret is invalid"))?,
        algorithm: record.algorithm.clone(),
        digits: record.digits,
        period: record.period,
    })
}

fn spec_from_input(
    input: &EntryInput,
    existing: Option<(&StoredEntry, &str)>,
) -> ApiResult<EntrySpec> {
    if let Some(uri) = input
        .otpauth_uri
        .as_deref()
        .filter(|uri| !uri.trim().is_empty())
    {
        let mut spec = totp::parse_otpauth_uri(uri)
            .map_err(|message| ApiError::bad_request("invalid_otpauth_uri", message))?;
        if let Some(label) = input
            .label
            .as_deref()
            .filter(|label| !label.trim().is_empty())
        {
            spec.label = label.trim().to_owned();
        }
        validate_spec(&spec)?;
        return Ok(spec);
    }

    let issuer = input
        .issuer
        .as_deref()
        .or_else(|| existing.map(|(record, _)| record.issuer.as_str()))
        .unwrap_or("")
        .trim()
        .to_owned();
    let account = input
        .account
        .as_deref()
        .or_else(|| existing.map(|(record, _)| record.account.as_str()))
        .unwrap_or("")
        .trim()
        .to_owned();
    let label = input
        .label
        .as_deref()
        .or_else(|| existing.map(|(record, _)| record.label.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            if issuer.is_empty() {
                account.clone()
            } else {
                issuer.clone()
            }
        });
    let secret = match input
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
    {
        Some(secret) => totp::normalize_secret(secret)
            .map_err(|message| ApiError::bad_request("invalid_secret", message))?,
        None => existing
            .map(|(_, secret)| secret.to_owned())
            .ok_or_else(|| ApiError::bad_request("missing_secret", "Secret is required"))?,
    };
    let algorithm = input
        .algorithm
        .as_deref()
        .or_else(|| existing.map(|(record, _)| record.algorithm.as_str()))
        .unwrap_or("SHA1")
        .trim()
        .to_ascii_uppercase();
    let digits = input
        .digits
        .or_else(|| existing.map(|(record, _)| record.digits))
        .unwrap_or(6);
    let period = input
        .period
        .or_else(|| existing.map(|(record, _)| record.period))
        .unwrap_or(30);
    let spec = EntrySpec {
        issuer,
        account,
        label,
        secret,
        algorithm,
        digits,
        period,
    };
    validate_spec(&spec)?;
    Ok(spec)
}

fn validate_spec(spec: &EntrySpec) -> ApiResult<()> {
    for (name, value, max_len) in [
        ("issuer", spec.issuer.as_str(), 120),
        ("account", spec.account.as_str(), 200),
        ("label", spec.label.as_str(), 120),
    ] {
        if value.chars().any(char::is_control) {
            return Err(ApiError::bad_request(
                "invalid_entry",
                format!("{name} contains an invalid control character"),
            ));
        }
        if value.chars().count() > max_len {
            return Err(ApiError::bad_request(
                "invalid_entry",
                format!("{name} is too long"),
            ));
        }
    }
    if spec.account.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_entry",
            "Account is required",
        ));
    }
    totp::build_totp(spec)
        .map(|_| ())
        .map_err(|message| ApiError::bad_request("invalid_entry", message))
}

fn timestamp_string(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::{spec_from_input, EntryInput};

    #[test]
    fn manual_input_uses_defaults() {
        let spec = spec_from_input(
            &EntryInput {
                otpauth_uri: None,
                issuer: Some("GitHub".to_owned()),
                account: Some("xin@example.com".to_owned()),
                label: None,
                secret: Some("jbsw y3dp ehpk 3pxp".to_owned()),
                algorithm: None,
                digits: None,
                period: None,
            },
            None,
        )
        .unwrap();
        assert_eq!(spec.algorithm, "SHA1");
        assert_eq!(spec.digits, 6);
        assert_eq!(spec.period, 30);
        assert_eq!(spec.label, "GitHub");
    }
}
