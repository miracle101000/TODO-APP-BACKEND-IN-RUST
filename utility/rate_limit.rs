use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    extract::Request,
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use metrics::counter;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};
use tracing::warn;

// one type alias — easier to pass around
pub type IpRateLimiter = Arc<DefaultKeyedRateLimiter<IpAddr>>;

// call this to build each limiter
pub fn make_limiter(per_second: u32, burst: u32) -> IpRateLimiter {
    Arc::new(RateLimiter::keyed(
        Quota::per_second(NonZeroU32::new(per_second).unwrap())
            .allow_burst(NonZeroU32::new(burst).unwrap()),
    ))
}

// the actual middleware — keyed per IP address
pub async fn rate_limit_middleware(
    State(limiter): State<IpRateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();

    match limiter.check_key(&addr.ip()) {
        Ok(_) => Ok(next.run(req).await),
        Err(_) => {
            warn!(ip = %addr.ip(), path = %path, "Rate limit exceeded");
            counter!("rate_limit.hits", "path" => path).increment(1);
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}