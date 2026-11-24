//! Request-timeout helper shared by every client-side exchange.

use std::future::Future;
use std::time::Duration;

use tokio::net::{TcpStream, ToSocketAddrs};

use crate::error::{EipError, Result};

/// Default bound on a client request/response exchange.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Default bound on opening the TCP connection itself.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Open a TCP connection, failing with [`EipError::Timeout`] if the connect
/// (including name resolution) takes longer than `limit`. `None` disables the
/// bound. On expiry the pending connect future is dropped, which cancels the
/// attempt. Refused or unreachable peers still fail fast with
/// [`EipError::Io`].
pub async fn connect_bounded<A: ToSocketAddrs>(
    addr: A,
    limit: Option<Duration>,
) -> Result<TcpStream> {
    bounded(limit, async { Ok(TcpStream::connect(addr).await?) }).await
}

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
