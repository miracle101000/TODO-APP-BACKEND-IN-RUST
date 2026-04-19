use axum::{extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}}, http::StatusCode, response::IntoResponse};
use jsonwebtoken::{DecodingKey, Validation, decode};

use crate::models::{AppState, JwtInterceptor, WsQuery};

pub async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
) -> impl IntoResponse {
    let token_data = decode::<JwtInterceptor>(
        &query.token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    );

    match token_data {
        Ok(data) => ws.on_upgrade(move |socket| handle_websocket(socket, state, data.claims)),
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    }
}

async fn handle_websocket(mut socket: WebSocket, state: AppState, interceptor: JwtInterceptor) {
    let mut rx = state.tx.subscribe();
    while let Ok(item) = rx.recv().await {
        if item.user_id != interceptor.user_token_or_id {
            continue;
        }
        match serde_json::to_string(&item) {
            Ok(json) => {
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(e) => eprintln!("Failed to serialize item: {}", e),
        }
    }
}