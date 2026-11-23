//! Request-timeout helper shared by every client-side exchange.

use std::future::Future;
use std::time::Duration;

use crate::error::{EipError, Result};

/// Default bound on a client request/response exchange.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Await `fut`, failing with [`EipError::Timeout`] if it takes longer than
/// `limit`. `None` disables the bound.
pub async fn bounded<T, F>(limit: Option<Duration>, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match limit {
        None => fut.await,
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => Err(EipError::Timeout(d)),
        },
    }
}
