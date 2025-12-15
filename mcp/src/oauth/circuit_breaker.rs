//! Circuit breaker for upstream API calls
//!
//! Provides resilience against upstream service failures by preventing
//! repeated calls to a failing service, allowing it time to recover.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Simple circuit breaker state
#[derive(Debug)]
enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing - reject requests
    HalfOpen, // Testing if service recovered
}

/// Circuit breaker for upstream OAuth API calls
///
/// Configuration:
/// - Opens after 5 consecutive failures
/// - Half-open after 30 seconds
/// - Closes after 2 consecutive successes in half-open state
pub(crate) struct OAuthCircuitBreaker {
    failure_count: AtomicUsize,
    success_count: AtomicUsize,
    last_failure_time: AtomicU64,
    failure_threshold: usize,
    half_open_timeout_secs: u64,
    success_threshold: usize,
}

impl OAuthCircuitBreaker {
    pub fn new() -> Self {
        Self {
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            last_failure_time: AtomicU64::new(0),
            failure_threshold: 5,
            half_open_timeout_secs: 30,
            success_threshold: 2,
        }
    }

    fn state(&self) -> CircuitState {
        let failures = self.failure_count.load(Ordering::Relaxed);
        let last_failure = self.last_failure_time.load(Ordering::Relaxed);

        if failures < self.failure_threshold {
            return CircuitState::Closed;
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        if now_secs - last_failure < self.half_open_timeout_secs {
            CircuitState::Open
        } else {
            CircuitState::HalfOpen
        }
    }

    pub fn is_call_permitted(&self) -> bool {
        !matches!(self.state(), CircuitState::Open)
    }

    pub fn record_success(&self) {
        let prev_failures = self.failure_count.swap(0, Ordering::Relaxed);

        if prev_failures > 0 {
            let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;

            if successes >= self.success_threshold {
                self.success_count.store(0, Ordering::Relaxed);
                tracing::info!(
                    event = "circuit_breaker_closed",
                    component = "oauth_upstream",
                    "Circuit breaker closed - upstream service recovered"
                );
            }
        }
    }

    pub fn record_failure(&self) {
        self.success_count.store(0, Ordering::Relaxed);
        let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.last_failure_time.store(now_secs, Ordering::Relaxed);

        if failures == self.failure_threshold {
            tracing::warn!(
                event = "circuit_breaker_opened",
                component = "oauth_upstream",
                consecutive_failures = failures,
                "Circuit breaker opened due to consecutive failures"
            );
        }
    }
}

pub(crate) fn create_oauth_circuit_breaker() -> Arc<OAuthCircuitBreaker> {
    Arc::new(OAuthCircuitBreaker::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_starts_closed() {
        let cb = OAuthCircuitBreaker::new();
        assert!(cb.is_call_permitted());
    }

    #[test]
    fn circuit_breaker_opens_after_threshold_failures() {
        let cb = OAuthCircuitBreaker::new();

        // Record failures up to threshold
        for _ in 0..5 {
            cb.record_failure();
        }

        // Circuit should now be open
        assert!(!cb.is_call_permitted());
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        let cb = OAuthCircuitBreaker::new();

        // Record some failures
        cb.record_failure();
        cb.record_failure();

        // Success should reset counter
        cb.record_success();

        assert!(cb.is_call_permitted());
        assert_eq!(cb.failure_count.load(Ordering::Relaxed), 0);
    }
}
