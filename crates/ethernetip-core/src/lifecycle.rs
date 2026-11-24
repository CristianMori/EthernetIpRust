//! Shared shutdown helpers for the server-side crates.

use std::time::Duration;

use tokio::task::JoinSet;

/// How long `shutdown()` waits for per-session tasks to finish on their own
/// before aborting the stragglers.
pub const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Wait up to `grace` for every task in `set` to finish, then abort whatever
/// is left and reap it. Sessions are expected to observe the shutdown signal
/// themselves; the abort is only the backstop for a task stuck in a write.
pub async fn drain_join_set(set: &mut JoinSet<()>, grace: Duration) {
    let graceful =
        tokio::time::timeout(grace, async { while set.join_next().await.is_some() {} }).await;
    if graceful.is_err() {
        tracing::warn!("{} session task(s) ignored shutdown, aborting", set.len());
        set.abort_all();
        while set.join_next().await.is_some() {}
    }
}
