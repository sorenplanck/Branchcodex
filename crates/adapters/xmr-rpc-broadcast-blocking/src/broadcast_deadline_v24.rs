//! Absolute HTTP deadline for new funding broadcasts. Reconciliation performed
//! later through the reader is independent; expiry never proves non-delivery.
use reqwest::blocking::{Client, RequestBuilder, Response};
use std::time::{Duration, Instant};
use xmr_spend_port::SpendPortError;

pub(super) fn require_before_v24(deadline: Option<Instant>) -> Result<(), SpendPortError> {
    match deadline {
        Some(deadline) if deadline <= Instant::now() => Err(SpendPortError::Retryable),
        _ => Ok(()),
    }
}

fn request_timeout_v24(deadline: Instant, now: Instant) -> Result<Duration, SpendPortError> {
    let remaining = deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .ok_or(SpendPortError::Retryable)?;
    Ok(remaining.min(Duration::from_secs(30)))
}

pub(super) fn send_before_v24(
    client: &Client,
    builder: RequestBuilder,
    deadline: Option<Instant>,
) -> Result<Response, SpendPortError> {
    let Some(deadline) = deadline else {
        return builder.send().map_err(|_| SpendPortError::Retryable);
    };
    let mut request = builder.build().map_err(|_| SpendPortError::Rejected)?;
    // Includes connect, send and the response body. No timeout can start again
    // from the duration captured before another RPC or a costly raw-byte audit.
    *request.timeout_mut() = Some(request_timeout_v24(deadline, Instant::now())?);
    client
        .execute(request)
        .map_err(|_| SpendPortError::Retryable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timeout_shrinks_across_preparation_and_cannot_extend_the_original_window() {
        let start = Instant::now();
        let end = start + Duration::from_secs(40);
        assert_eq!(request_timeout_v24(end, start), Ok(Duration::from_secs(30)));
        assert_eq!(
            request_timeout_v24(end, start + Duration::from_secs(35)),
            Ok(Duration::from_secs(5))
        );
        assert_eq!(
            request_timeout_v24(end, end),
            Err(SpendPortError::Retryable)
        );
        assert_eq!(
            request_timeout_v24(end, end + Duration::from_nanos(1)),
            Err(SpendPortError::Retryable)
        );
    }
    #[test]
    fn expired_request_cannot_open_a_post_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = Client::builder().no_proxy().build().unwrap();
        let request = client
            .post(format!(
                "http://{}/send_raw_transaction",
                listener.local_addr().unwrap()
            ))
            .json(&serde_json::json!({"tx_as_hex":"synthetic-not-submitted","do_not_relay":false}));
        assert!(matches!(
            send_before_v24(&client, request, Some(Instant::now())),
            Err(SpendPortError::Retryable)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
