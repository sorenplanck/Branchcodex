//! Absolute read budgets; no mutation of the original reader or broadcast state.
use super::*;
use std::time::{Duration, Instant};

impl BlockingMoneroDaemonReaderV1 {
    /// Clone the same endpoint/client with an absolute observation deadline.
    /// Every read, including nested genesis/header rechecks, receives only the
    /// remaining time. An existing deadline is never extended; maximum is 60s.
    /// The original reader and legacy callers retain their existing timeouts.
    pub fn with_observation_deadline_v24(&self, deadline: Instant) -> Result<Self, SpendPortError> {
        let now = Instant::now();
        let deadline = observation_deadline_v24(deadline, self.observation_deadline_v24, now)?;
        let mut reader = self.clone();
        reader.observation_deadline_v24 = Some(deadline);
        Ok(reader)
    }
}

fn observation_deadline_v24(
    original: Instant,
    inherited: Option<Instant>,
    now: Instant,
) -> Result<Instant, SpendPortError> {
    let cap = now
        .checked_add(Duration::from_secs(60))
        .ok_or(SpendPortError::Rejected)?;
    let deadline = original.min(inherited.unwrap_or(original)).min(cap);
    if deadline <= now {
        return Err(SpendPortError::Retryable);
    }
    Ok(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_budget_never_extends_an_inherited_deadline_v24() -> Result<(), SpendPortError> {
        let start = Instant::now();
        let original = start + Duration::from_secs(40);
        assert_eq!(
            observation_deadline_v24(start + Duration::from_secs(180), None, start)?,
            start + Duration::from_secs(60)
        );
        for elapsed in [0, 15, 39] {
            assert_eq!(
                observation_deadline_v24(
                    start + Duration::from_secs(180),
                    Some(original),
                    start + Duration::from_secs(elapsed)
                )?,
                original
            );
        }
        assert_eq!(
            observation_deadline_v24(original, None, original),
            Err(SpendPortError::Retryable)
        );
        Ok(())
    }

    #[test]
    fn expired_reader_methods_never_contact_even_genesis_v24(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let original =
            BlockingMoneroDaemonReaderV1::new(format!("http://{}", listener.local_addr()?))?;
        assert!(original.observation_deadline_v24.is_none());
        assert!(matches!(
            original.with_observation_deadline_v24(Instant::now()),
            Err(SpendPortError::Retryable)
        ));
        // Deterministic expired clone seam: no sleep or live daemon required.
        let mut expired = original.clone();
        expired.observation_deadline_v24 = Some(Instant::now());
        assert!(matches!(
            expired.transaction_raw_v23([1; 32], [2; 32]),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.ring_members_v23(&(0..16).collect::<Vec<_>>(), [2; 32]),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.transaction_observation_v5([1; 32], [2; 32]),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.transaction_location([1; 32]),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.daemon_height(),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.time_header_at_v23(0),
            Err(SpendPortError::Retryable)
        ));
        assert!(matches!(
            expired.key_image_spent([1; 32]),
            Err(SpendPortError::Retryable)
        ));
        assert_eq!(
            listener.accept().err().map(|error| error.kind()),
            Some(std::io::ErrorKind::WouldBlock)
        );
        assert!(original.observation_deadline_v24.is_none());
        Ok(())
    }
}
