use dxp1_clsag_lab::preparation_gate::{
    GateError, PreparationBinding, PreparationGate, PreparationState,
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

fn binding() -> PreparationBinding {
    PreparationBinding {
        capsule_link: [7; 64],
        received: 1000,
    }
}
fn root(name: &str) -> PathBuf {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "dxp1-preparation-{}-{name}-{serial}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn recovery_excludes_exchange_and_pins_original_job_across_reopen() {
    let root = root("recovery");
    let path = root.join("gate");
    assert!(PreparationGate::open(&path, binding()).is_err());
    let mut gate = PreparationGate::create(&path, binding()).unwrap();
    assert_eq!(gate.state().unwrap(), PreparationState::Private);
    assert!(gate.require_exchange([1; 32]).is_err());
    assert!(gate.claim_recovery([0; 32]).is_err());
    gate.claim_recovery([2; 32]).unwrap();
    assert!(gate.begin_exchange([1; 32]).is_err());
    drop(gate);
    let bytes = fs::read(&path).unwrap();
    let mut gate = PreparationGate::open(&path, binding()).unwrap();
    gate.claim_recovery([2; 32]).unwrap();
    assert!(gate.claim_recovery([3; 32]).is_err());
    assert!(gate.require_exchange([1; 32]).is_err());
    drop(gate);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(PreparationGate::create(&path, binding()).is_err());
    let mut changed = binding();
    changed.received += 1;
    assert!(PreparationGate::open(&path, changed).is_err());
    changed = binding();
    changed.capsule_link[0] ^= 1;
    assert!(PreparationGate::open(&path, changed).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_exchange_never_authorizes_the_private_recovery_path() {
    let root = root("exchange");
    let path = root.join("gate");
    let mut gate = PreparationGate::create(&path, binding()).unwrap();
    gate.begin_exchange([1; 32]).unwrap();
    let failed_send: Result<(), &str> = Err("simulated lost connection before acknowledgement");
    assert!(failed_send.is_err());
    drop(gate);
    let mut gate = PreparationGate::open(&path, binding()).unwrap();
    gate.require_exchange([1; 32]).unwrap();
    assert!(gate.require_exchange([2; 32]).is_err());
    assert!(gate.begin_exchange([1; 32]).is_err());
    assert!(gate.claim_recovery([2; 32]).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn damaged_partial_public_and_symlink_records_fail_closed() {
    let root = root("damage");
    let path = root.join("gate");
    let mut gate = PreparationGate::create(&path, binding()).unwrap();
    let header = fs::metadata(&path).unwrap().len() as usize;
    gate.begin_exchange([1; 32]).unwrap();
    drop(gate);
    let bytes = fs::read(&path).unwrap();
    for i in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        fs::write(&path, changed).unwrap();
        assert!(PreparationGate::open(&path, binding()).is_err(), "byte {i}");
        // Removing an entire committed event is malicious storage rollback,
        // which this journal explicitly does not claim to detect.
        if i != header {
            fs::write(&path, &bytes[..i]).unwrap();
            assert!(PreparationGate::open(&path, binding()).is_err());
        }
    }
    let mut extended = bytes.clone();
    extended.push(0);
    fs::write(&path, extended).unwrap();
    assert!(PreparationGate::open(&path, binding()).is_err());
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(PreparationGate::open(&path, binding()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&path, root.join("link")).unwrap();
    assert!(PreparationGate::open(&root.join("link"), binding()).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn child(root: &std::path::Path, mode: &str) -> i32 {
    Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "gate_child"])
        .env("DXP1_GATE_TEST_ROOT", root)
        .env("DXP1_GATE_TEST_MODE", mode)
        .output()
        .unwrap()
        .status
        .code()
        .unwrap()
}

#[test]
fn abrupt_process_exit_keeps_the_choice_without_destructors() {
    for (mode, exit) in [("exchange", 77), ("recovery", 78)] {
        let root = root(mode);
        let path = root.join("gate");
        drop(PreparationGate::create(&path, binding()).unwrap());
        assert_eq!(child(&root, mode), exit);
        let mut gate = PreparationGate::open(&path, binding()).unwrap();
        if mode == "exchange" {
            gate.require_exchange([1; 32]).unwrap();
            assert!(gate.claim_recovery([2; 32]).is_err());
        } else {
            gate.claim_recovery([2; 32]).unwrap();
            assert!(gate.begin_exchange([1; 32]).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn another_process_cannot_race_the_locked_preparation_choice() {
    let root = root("lock");
    let path = root.join("gate");
    let mut gate = PreparationGate::create(&path, binding()).unwrap();
    assert_eq!(child(&root, "locked"), 79);
    gate.claim_recovery([2; 32]).unwrap();
    drop(gate);
    assert_eq!(child(&root, "denied"), 80);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "invoked by parent tests in a fresh process"]
fn gate_child() {
    let root = PathBuf::from(std::env::var_os("DXP1_GATE_TEST_ROOT").unwrap());
    let mode = std::env::var("DXP1_GATE_TEST_MODE").unwrap();
    if mode == "locked" {
        assert!(matches!(
            PreparationGate::open(&root.join("gate"), binding()),
            Err(GateError::Locked)
        ));
        std::process::exit(79);
    }
    let mut gate = PreparationGate::open(&root.join("gate"), binding()).unwrap();
    match mode.as_str() {
        "exchange" => {
            gate.begin_exchange([1; 32]).unwrap();
            std::process::exit(77);
        }
        "recovery" => {
            gate.claim_recovery([2; 32]).unwrap();
            std::process::exit(78);
        }
        "denied" => {
            assert!(gate.begin_exchange([1; 32]).is_err());
            std::process::exit(80);
        }
        _ => panic!("unknown fixture mode"),
    }
}
