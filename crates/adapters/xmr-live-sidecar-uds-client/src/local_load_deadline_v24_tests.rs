//! No daemon or GPL process: bounded private UDS peers exercise public LOAD.
use super::tests::{read_test_frame, socket_scratch_dir, write_test_frame};
use super::*;
use std::os::unix::net::{UnixListener, UnixStream};
use xmr_live_sidecar_api::LocalRefundLoadRequestV24;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: [u8; 32] = [7; 32];

fn request() -> LocalRefundLoadRequestV24 {
    LocalRefundLoadRequestV24 {
        api_version: 24,
        request_nonce: [1; 32],
        effect_id: [1; 32],
        network_genesis: [2; 32],
        route: [3; 32],
        session: [4; 32],
        terms: [5; 32],
        fencing_epoch: 1,
        semantic_digest: [6; 32],
        dom_refund_tx_hash: [7; 32],
        graph_digest: [8; 32],
        settlement_id: [9; 32],
        funding_tx_hash: [10; 32],
        funded_amount: 1000,
        destination: "deadline-public-scope-only".into(),
        expected_spend_public_key: [11; 32],
        max_fee: 10,
        auth_tag: [0; 32],
    }
}

#[test]
fn expired_public_load_does_not_connect_v24() -> TestResult {
    let directory = socket_scratch_dir();
    let path = directory.path().join("expired.sock");
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
    assert!(matches!(
        client.load_local_refund_with_deadline_v24(request(), Instant::now()),
        Err(SpendPortError::Retryable)
    ));
    assert_eq!(
        listener.accept().err().map(|error| error.kind()),
        Some(std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn public_load_preserves_original_deadline_and_caps_sixty_seconds_v24() -> TestResult {
    use super::build_proof_v23::local_load_deadline_v24;
    let start = Instant::now();
    let original = start + Duration::from_secs(50);
    for elapsed in [0, 1, 25, 49] {
        assert_eq!(
            local_load_deadline_v24(
                original,
                start + Duration::from_secs(elapsed),
                Duration::from_secs(180)
            )?,
            original
        );
    }
    assert!(matches!(
        local_load_deadline_v24(original, original, Duration::from_secs(180)),
        Err(SpendPortError::Retryable)
    ));
    assert_eq!(
        local_load_deadline_v24(
            start + Duration::from_secs(180),
            start,
            Duration::from_secs(180)
        )?,
        start + Duration::from_secs(60)
    );
    assert_eq!(
        local_load_deadline_v24(original, start, Duration::from_millis(25))?,
        start + Duration::from_millis(25)
    );
    Ok(())
}

fn accept_bounded(listener: UnixListener) -> std::io::Result<UnixStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn trickle(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(
        &u32::try_from(bytes.len())
            .map_err(std::io::Error::other)?
            .to_be_bytes(),
    )?;
    for byte in bytes {
        stream.write_all(&[*byte])?;
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn public_load_deadline_covers_trickling_hello_and_never_sends_request_v24() -> TestResult {
    let directory = socket_scratch_dir();
    let path = directory.path().join("hello.sock");
    let listener = UnixListener::bind(&path)?;
    let peer = std::thread::spawn(move || -> std::io::Result<bool> {
        let mut stream = accept_bounded(listener)?;
        let hello: SidecarHelloV1 = serde_json::from_slice(&read_test_frame(&mut stream)?)?;
        let proof = SidecarHelloProofV1 {
            api_version: API_VERSION_V2,
            proof: SidecarAuthKey::new(KEY)
                .map_err(std::io::Error::other)?
                .challenge_proof(&hello.challenge_nonce)
                .map_err(std::io::Error::other)?,
        };
        let _ = trickle(&mut stream, &serde_json::to_vec(&proof)?);
        let mut byte = [0];
        Ok(match stream.read(&mut byte) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            _ => false,
        })
    });
    let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
    let start = Instant::now();
    let result =
        client.load_local_refund_with_deadline_v24(request(), start + Duration::from_millis(300));
    assert!(matches!(result, Err(SpendPortError::Retryable)));
    assert!(peer.join().map_err(|_| "hello peer panicked")??);
    assert!(start.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn public_load_response_uses_remaining_not_the_configured_180_seconds_v24() -> TestResult {
    let directory = socket_scratch_dir();
    let path = directory.path().join("response.sock");
    let listener = UnixListener::bind(&path)?;
    let peer = std::thread::spawn(move || -> std::io::Result<bool> {
        let mut stream = accept_bounded(listener)?;
        let hello: SidecarHelloV1 = serde_json::from_slice(&read_test_frame(&mut stream)?)?;
        let key = SidecarAuthKey::new(KEY).map_err(std::io::Error::other)?;
        let proof = SidecarHelloProofV1 {
            api_version: API_VERSION_V2,
            proof: key
                .challenge_proof(&hello.challenge_nonce)
                .map_err(std::io::Error::other)?,
        };
        write_test_frame(&mut stream, &serde_json::to_vec(&proof)?)?;
        let envelope: SidecarRequestV2 = serde_json::from_slice(&read_test_frame(&mut stream)?)?;
        let SidecarRequestV2::LoadLocalRefundWithProofsV24(actual) = envelope else {
            return Ok(false);
        };
        let mut expected = request();
        key.sign_local_refund_load_v24(&mut expected)
            .map_err(std::io::Error::other)?;
        let response = SidecarResponseV2::Error(xmr_live_sidecar_api::SidecarErrorBody {
            code: "not-a-timeout".into(),
            message: "complete response would reject, not retry".into(),
            retryable: false,
        });
        let _ = trickle(&mut stream, &serde_json::to_vec(&response)?);
        Ok(actual == expected)
    });
    let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
    let start = Instant::now();
    let result =
        client.load_local_refund_with_deadline_v24(request(), start + Duration::from_millis(300));
    assert!(matches!(result, Err(SpendPortError::Retryable)));
    assert!(peer.join().map_err(|_| "response peer panicked")??);
    assert!(start.elapsed() < Duration::from_secs(2));
    Ok(())
}
