use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../frontend/dist/"]
struct Assets;

pub async fn fallback(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path == "health" || path.starts_with("api/") {
        return (
            StatusCode::NOT_FOUND,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            r#"{"error":"not_found","message":"Not found"}"#,
        )
            .into_response();
    }

    let asset_path = if path.is_empty() { "index.html" } else { path };
    let Some(asset) = Assets::get(asset_path).or_else(|| Assets::get("index.html")) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Frontend assets are not built. Run `npm run build` in frontend/.",
        )
            .into_response();
    };
    let content_type = mime_guess::from_path(asset_path)
        .first_raw()
        .unwrap_or("application/octet-stream");
    let cache_control = if asset_path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .body(Body::from(asset.data.into_owned()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
