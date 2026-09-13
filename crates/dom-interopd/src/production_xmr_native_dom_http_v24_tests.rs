//! Per-connection transport failures are not failures of the native ledger.
//! Only errors marked at an actual socket boundary may be retried by accept.
use super::*;
use std::io;

#[derive(Debug)]
struct PeerIoV24(io::Error);
impl std::fmt::Display for PeerIoV24 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "local DOM peer transport: {}", self.0)
    }
}
impl std::error::Error for PeerIoV24 {}

pub(super) fn socket_io_v24<T>(result: io::Result<T>) -> Result<T> {
    result.map_err(|error| Box::new(PeerIoV24(error)) as Box<dyn std::error::Error>)
}

pub(super) fn peer_io_v24(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<PeerIoV24>().is_some()
}

pub(super) fn finish_connection_v24(result: Result<()>) -> Result<()> {
    match result {
        Err(error)
            if error.downcast_ref::<PeerIoV24>().is_some_and(|error| {
                matches!(
                    error.0.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::NotConnected
                )
            }) =>
        {
            Ok(())
        }
        other => other,
    }
}

pub(super) fn read_header_v24(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    while !header.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let n = socket_io_v24(stream.read(&mut buffer))?;
        if n == 0 {
            return socket_io_v24(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer disconnected before HTTP header",
            )));
        }
        if header.len() + n > 8192 {
            return Err("snapshot request bound".into());
        }
        header.extend_from_slice(&buffer[..n]);
    }
    Ok(header)
}

pub(super) fn write_json_v24(stream: &mut impl Write, status: &str, response: &[u8]) -> Result<()> {
    socket_io_v24(write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()))?;
    socket_io_v24(stream.write_all(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    fn accept_bounded(listener: &TcpListener) -> Result<TcpStream> {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, address)) => {
                    if !address.ip().is_loopback() {
                        return Err("test peer escaped loopback".into());
                    }
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= until {
                        return Err("test accept deadline".into());
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn connect(address: std::net::SocketAddr) -> Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        Ok(stream)
    }

    #[test]
    fn native_dom_get_peer_timeout_keeps_next_connection_available_v24() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || -> std::result::Result<(), String> {
            (|| -> Result<()> {
                let mut first = accept_bounded(&listener)?;
                first.set_read_timeout(Some(Duration::from_millis(30)))?;
                let error = read_header_v24(&mut first).expect_err("partial GET must time out");
                assert!(peer_io_v24(error.as_ref()));
                finish_connection_v24(Err(error))?;
                drop(first);
                ready_tx.send(())?;
                let mut next = accept_bounded(&listener)?;
                let request = read_header_v24(&mut next)?;
                assert_eq!(
                    request,
                    b"GET /chain/scan/scriptless/v1?from=0 HTTP/1.1\r\n\r\n"
                );
                finish_connection_v24(write_json_v24(&mut next, "200 OK", b"{\"read_only\":true}"))
            })()
            .map_err(|error| error.to_string())
        });
        let client_result = (|| -> Result<()> {
            let mut expired = connect(address)?;
            expired.write_all(b"GET /chain/scan/scriptless/v1?from=0 HTTP/1.1\r\n")?;
            ready_rx.recv_timeout(Duration::from_secs(2))?;
            drop(expired);
            let mut next = connect(address)?;
            next.write_all(b"GET /chain/scan/scriptless/v1?from=0 HTTP/1.1\r\n\r\n")?;
            let mut response = String::new();
            next.read_to_string(&mut response)?;
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with("{\"read_only\":true}"));
            Ok(())
        })();
        let worker_result = worker
            .join()
            .map_err(|_| "HTTP regression worker panicked")?;
        client_result?;
        worker_result.map_err(Into::into)
    }

    /// Inject the precise transport failure after admission, not a fake chain
    /// receipt. The follow-up GET only checks retained exact bytes and the
    /// admission count; native finality is exercised by the daemon scenarios.
    struct LostAck<'a>(&'a mut TcpStream);
    impl Read for LostAck<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.0.read(buffer)
        }
    }
    impl Write for LostAck<'_> {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected lost ACK",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native_dom_post_lost_ack_preserves_exact_admission_for_readback_v24() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let worker = thread::spawn(move || -> std::result::Result<(), String> {
            (|| -> Result<()> {
                let mut retained = None;
                let mut admissions = 0usize;
                let mut first = accept_bounded(&listener)?;
                let header = read_header_v24(&mut first)?;
                assert!(header.starts_with(b"POST /tx/submit HTTP/1.1\r\n"));
                let result = evolving_v23::submit_http_with_v24(
                    &mut LostAck(&mut first),
                    &header,
                    |bytes| {
                        admissions += 1;
                        retained = Some(bytes.to_vec());
                        // Opaque transport seam, never a production finality token.
                        Ok(json!({"transport_test_admitted":true}))
                    },
                );
                assert!(result
                    .as_ref()
                    .is_err_and(|error| peer_io_v24(error.as_ref())));
                finish_connection_v24(result)?;
                drop(first);
                let mut next = accept_bounded(&listener)?;
                assert_eq!(
                    read_header_v24(&mut next)?,
                    b"GET /retained HTTP/1.1\r\n\r\n"
                );
                assert_eq!(admissions, 1);
                assert_eq!(retained.as_deref(), Some([0x12, 0x34, 0xab].as_slice()));
                write_json_v24(
                    &mut next,
                    "200 OK",
                    &serde_json::to_vec(&json!({
                        "exact_bytes":hex::encode(retained.as_ref().ok_or("admission lost")?),
                        "admissions":admissions
                    }))?,
                )
            })()
            .map_err(|error| error.to_string())
        });
        let client_result = (|| -> Result<()> {
            let body = b"{\"tx_hex\":\"1234ab\"}";
            let mut post = connect(address)?;
            write!(
                post,
                "POST /tx/submit HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )?;
            post.write_all(body)?;
            let mut ack = Vec::new();
            post.read_to_end(&mut ack)?;
            assert!(
                ack.is_empty(),
                "injected lost ACK must not expose a response"
            );
            let mut get = connect(address)?;
            get.write_all(b"GET /retained HTTP/1.1\r\n\r\n")?;
            let mut response = String::new();
            get.read_to_string(&mut response)?;
            let (_, body) = response
                .split_once("\r\n\r\n")
                .ok_or("readback body absent")?;
            assert_eq!(
                serde_json::from_str::<Value>(body)?,
                json!({"exact_bytes":"1234ab","admissions":1})
            );
            Ok(())
        })();
        let worker_result = worker
            .join()
            .map_err(|_| "HTTP regression worker panicked")?;
        client_result?;
        worker_result.map_err(Into::into)
    }

    #[test]
    fn native_dom_socket_retry_never_swallows_storage_scope_or_unknown_errors_v24() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(finish_connection_v24(socket_io_v24(Err(io::Error::from(kind)))).is_ok());
            // The same kind from a disk/ledger operation is NOT a socket tag.
            assert!(finish_connection_v24(Err(Box::new(io::Error::from(kind)))).is_err());
        }
        assert!(finish_connection_v24(socket_io_v24(Err(io::Error::from(
            io::ErrorKind::PermissionDenied
        ))))
        .is_err());
        assert!(finish_connection_v24(Err("canonical ancestry mismatch".into())).is_err());
        assert!(finish_connection_v24(Err("negotiated scope mismatch".into())).is_err());
    }

    #[test]
    fn native_dom_post_storage_timeout_is_rejection_not_peer_retry_or_acceptance_v24() -> Result<()>
    {
        let body = b"{\"tx_hex\":\"1234ab\"}";
        let mut request = format!(
            "POST /tx/submit HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let mut response = io::Cursor::new(Vec::<u8>::new());
        let mut attempts = 0usize;
        let result = evolving_v23::submit_http_with_v24(&mut response, &request, |bytes| {
            attempts += 1;
            assert_eq!(bytes, &[0x12, 0x34, 0xab]);
            let failure = io::Error::new(io::ErrorKind::TimedOut, "storage deadline");
            assert!(!peer_io_v24(&failure));
            Err(Box::new(failure))
        });
        // Existing POST semantics: admission errors produce a refusal response,
        // not a retryable socket tag and not an accepted transaction receipt.
        assert!(result.is_ok());
        finish_connection_v24(result)?;
        assert_eq!(attempts, 1);
        let response = String::from_utf8(response.into_inner())?;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(!response.contains("200 OK"));
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or("refusal body absent")?;
        let refusal: Value = serde_json::from_str(body)?;
        assert_eq!(refusal["accepted"], json!(false));
        assert_eq!(refusal["confirmed"], json!(false));
        assert_eq!(refusal["relayed"], json!(false));
        assert_eq!(refusal["state"], json!("rejected"));
        assert_eq!(refusal["tx_hash"], Value::Null);
        assert_eq!(refusal["error"], json!("native local admission refused"));
        Ok(())
    }

    #[test]
    fn native_dom_incomplete_post_never_reaches_admission_v24() {
        let mut stream = io::Cursor::new(Vec::<u8>::new());
        let result = evolving_v23::submit_http_with_v24(
            &mut stream,
            b"POST /tx/submit HTTP/1.1\r\nContent-Length: 12\r\n\r\n",
            |_| panic!("truncated request cannot admit bytes"),
        );
        assert!(result
            .as_ref()
            .is_err_and(|error| peer_io_v24(error.as_ref())));
        assert!(finish_connection_v24(result).is_ok());
        assert!(stream.into_inner().is_empty());
    }
}
