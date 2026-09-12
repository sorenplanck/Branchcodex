#!/usr/bin/env python3
"""Run real repository test commands and retain observed outcomes, never a security score."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest():
    # Include staged, unstaged and new source files, excluding generated evidence.
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    paths = sorted(set(os.fsdecode(p) for p in raw.split(b"\0") if p))
    digest = hashlib.sha256()
    for name in paths:
        if name.startswith("artifacts/"):
            continue
        path = ROOT / name
        if path.is_file():
            digest.update(name.encode() + b"\0" + bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def commands(mode, evidence_directory):
    offline = [("independent-oracles", [sys.executable, "-m", "unittest", "discover",
                 "-s", "scripts/tests", "-p", "test_*_oracle.py", "-v"], {})]
    if mode == "offline":
        return offline
    trace = evidence_directory / "rust-route-trace-v4.json"
    trace_env = {"DOM_INTEROP_V4_ROUTE_TRACE": str(trace)}
    trace_verification = ("rust-route-independent-verification", [sys.executable,
        "scripts/route_trace_oracle.py", str(trace)], {})
    time_fixture = evidence_directory / "rust-time-evidence-v5.json"
    production_env = {**trace_env, "DOM_INTEROP_V5_TIME_FIXTURE": str(time_fixture)}
    production = ("production", ["cargo", "test", "-p", "dom-interopd", "--no-default-features",
        "--features", "production", "--lib", "--tests", "--locked", "--profile", "crypto-test", "--no-fail-fast",
        "--", "--nocapture", "--test-threads=1"], production_env)
    time_verification = ("rust-time-independent-verification", [sys.executable,
        "scripts/time_evidence_oracle.py", str(time_fixture)], {})
    monero = ("monero-rpc-and-actuator-v5", ["cargo", "test", "--locked", "-p",
        "xmr-rpc-broadcast-blocking", "-p", "xmr-actuator"], {})
    driver_fixture = evidence_directory / "rust-driver-claim-v6.json"
    driver_env = {"DOM_INTEROP_V6_DRIVER_CLAIM": str(driver_fixture)}
    driver_verification = ("rust-driver-final-signature-verification", [sys.executable,
        "scripts/bitcoin_driver_oracle.py", str(driver_fixture)], {})
    if mode == "v6":
        return offline + [
            ("bitcoin-driver-v6", ["cargo", "test", "--locked", "-p", "btc-actuator",
                "--test", "participant_signing", "driver_v6"], driver_env),
            driver_verification, production, trace_verification, time_verification,
        ]
    if mode == "runtime":
        return offline + [monero, production, trace_verification, time_verification]
    if mode == "routing":
        cargo = ["cargo", "test", "--locked", "-p", "dom-interopd", "--no-default-features",
                 "--features", "production", "--lib"]
        return offline + [
            ("route-router-v4", cargo + ["route_tests_v4"], trace_env),
            ("evm-recovery-v4", cargo + ["evm_recovery_tests_v4"], {}),
            ("store-isolation-v4", cargo + ["two_leg_store_preflight"], {}),
            trace_verification,
        ]
    specs = offline + [
        ("workspace-lock", ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"], {}),
        ("bitcoin", ["cargo", "test", "--locked", "-p", "btc-crypto", "-p", "adapter-btc", "-p", "btc-actuator"],
         {**driver_env, "DOM_INTEROP_V3_PUBLIC_FIXTURE": str(evidence_directory / "rust-participant-round-v3.json")}),
        driver_verification,
        ("rust-participant-independent-verification", [sys.executable, "scripts/bitcoin_participant_oracle.py",
         str(evidence_directory / "rust-participant-round-v3.json")], {}),
        ("solana-adapters", ["cargo", "test", "--locked", "-p", "kaystra-core", "-p", "solana-kaystra-source", "-p", "solana-escrow-wire", "-p", "solana-program-client", "-p", "solana-observer", "-p", "solana-evidence", "-p", "solana-observation-store", "-p", "solana-observer-pump"], {}),
        ("solana-program-host", ["cargo", "test", "--manifest-path", "programs/dom-solana-escrow/Cargo.toml", "--locked"], {}),
        monero,
        production,
        trace_verification,
        time_verification,
    ]
    if mode == "full":
        specs.extend([
            ("bitcoin-regtest", ["bash", "scripts/f5-regtest-e2e.sh"], {}),
            ("evm-deep", ["forge", "test", "--root", "contracts"], {"FOUNDRY_PROFILE": "deep"}),
            ("evm-anvil", ["bash", "scripts/e2e_anvil.sh"], {}),
        ])
    return specs


def start_test_command(name, env, evidence_directory):
    """Literal process targets keep the CI automation closure inspectable.

    Names select a closed dispatch table; no executable, script or argument
    comes from input files. Oracle input filenames are fixed inside this run.
    """
    if name == 'independent-oracles':
        return subprocess.Popen(['python3', '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-p', 'test_*_oracle.py', '-v'], cwd=ROOT, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'route-router-v4':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', 'route_tests_v4'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'evm-recovery-v4':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', 'evm_recovery_tests_v4'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'store-isolation-v4':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', 'two_leg_store_preflight'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'rust-route-independent-verification':
        # Fixed module import locations; an evidence file cannot choose code.
        env = {**env, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "scripts")))}
        return subprocess.Popen(['python3', '-m', 'scripts.route_trace_oracle', 'rust-route-trace-v4.json'], cwd=evidence_directory, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'monero-rpc-and-actuator-v5':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'xmr-rpc-broadcast-blocking', '-p', 'xmr-actuator'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--tests', '--locked', '--profile', 'crypto-test', '--no-fail-fast', '--', '--nocapture', '--test-threads=1'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'rust-time-independent-verification':
        # Fixed module import locations; an evidence file cannot choose code.
        env = {**env, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "scripts")))}
        return subprocess.Popen(['python3', '-m', 'scripts.time_evidence_oracle', 'rust-time-evidence-v5.json'], cwd=evidence_directory, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'bitcoin-driver-v6':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'btc-actuator', '--test', 'participant_signing', 'driver_v6'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'rust-driver-final-signature-verification':
        # Fixed module import locations; an evidence file cannot choose code.
        env = {**env, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "scripts")))}
        return subprocess.Popen(['python3', '-m', 'scripts.bitcoin_driver_oracle', 'rust-driver-claim-v6.json'], cwd=evidence_directory, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'workspace-lock':
        return subprocess.Popen(['cargo', 'metadata', '--locked', '--format-version', '1', '--no-deps'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'bitcoin':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'btc-crypto', '-p', 'adapter-btc', '-p', 'btc-actuator'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'rust-participant-independent-verification':
        # Fixed module import locations; an evidence file cannot choose code.
        env = {**env, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "scripts")))}
        return subprocess.Popen(['python3', '-m', 'scripts.bitcoin_participant_oracle', 'rust-participant-round-v3.json'], cwd=evidence_directory, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'solana-adapters':
        return subprocess.Popen(['cargo', 'test', '--locked', '-p', 'kaystra-core', '-p', 'solana-kaystra-source', '-p', 'solana-escrow-wire', '-p', 'solana-program-client', '-p', 'solana-observer', '-p', 'solana-evidence', '-p', 'solana-observation-store', '-p', 'solana-observer-pump'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'solana-program-host':
        return subprocess.Popen(['cargo', 'test', '--manifest-path', 'programs/dom-solana-escrow/Cargo.toml', '--locked'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'bitcoin-regtest':
        return subprocess.Popen(['bash', 'scripts/f5-regtest-e2e.sh'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'evm-deep':
        return subprocess.Popen(['forge', 'test', '--root', 'contracts'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'evm-anvil':
        return subprocess.Popen(['bash', 'scripts/e2e_anvil.sh'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'format-workspace':
        return subprocess.Popen(['cargo', 'fmt', '--all'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'format-solana-program':
        return subprocess.Popen(['cargo', 'fmt', '--manifest-path', 'programs/dom-solana-escrow/Cargo.toml'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    raise ValueError("unknown test command")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "routing", "runtime", "v6", "components", "full"), default="components")
    parser.add_argument("--format", action="store_true", help="run rustfmt before testing; records the resulting source digest")
    args = parser.parse_args()
    if args.mode == "offline" and args.format:
        parser.error("--format requires a Rust test mode")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_root = ROOT / "artifacts" / "interop-hardening"
    evidence_root.mkdir(parents=True, exist_ok=True)
    # Separate PID namespaces may reuse pid/time. Exclusive random suffixes
    # keep concurrent runs from colliding or mixing their evidence.
    out = Path(tempfile.mkdtemp(prefix=f"{stamp}-{args.mode}-{os.getpid()}-", dir=evidence_root))
    report = {
        "schema_version": 1, "scope": "repository-test-commands",
        "mode": args.mode, "started_utc": stamp, "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT).decode().strip(), "source_sha256_before": source_digest(),
        "status": "incomplete", "checks": [],
        "limits": ["Offline checks use public BIP vectors and synthetic transactions, not production swaps.",
                   "Component success does not certify complete production routes.",
                   "V4 routing tests use the real router with instrumented children; EVM recovery uses mock RPC.",
                   "V5 tests use local HTTP fixtures, signed test authorities and real local persistence, not live chain swaps.",
                   "The time oracle checks wire/signatures/public scopes, not the full runtime time ladder or chain ancestry.",
                   "V6 driver tests use real Unix sockets, MuSig2 and journals with synthetic funding/anchors; they are not live-chain routes.",
                   "V6 economic witnesses verify per-asset accounting only; consensus and inclusion require external verification.",
                   "Solana host tests are not SBF/validator execution.",
                   "This report does not estimate mainnet loss probability."],
    }
    report_path = out / "report.json"

    def save():
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(report_path)

    save()
    required = ["git"]
    if args.mode != "offline":
        required += ["cargo", "rustc", "cc", "clang", "cmake", "pkg-config"]
    if args.mode == "full":
        required += ["bitcoind", "bitcoin-cli", "forge", "anvil", "curl"]
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        report.update(status="blocked", missing_tools=missing)
        save()
        print("Missing tools: " + ", ".join(missing), file=sys.stderr)
        print(f"Observed report: {report_path}")
        return 2
    specs = commands(args.mode, out)
    if args.format:
        specs = [
            ("format-workspace", ["cargo", "fmt", "--all"], {}),
            ("format-solana-program", ["cargo", "fmt", "--manifest-path", "programs/dom-solana-escrow/Cargo.toml"], {}),
        ] + specs
    failed = False
    for name, command, extra_env in specs:
        log = out / f"{name}.log"
        print(f"\n[{name}] {' '.join(command)}", flush=True)
        begin = time.monotonic()
        entry = {"id": name, "command": command, "status": "running", "log": log.name}
        report["checks"].append(entry)
        save()
        env = os.environ.copy()
        env.update(extra_env)
        env["CARGO_TERM_COLOR"] = "never"
        try:
            with log.open("wb") as stream:
                process = start_test_command(name, env, out)
                entry["executed_command"] = process.args
                save()
                for line in iter(process.stdout.readline, b""):
                    stream.write(line)
                    stream.flush()
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                code = process.wait()
        except OSError as error:
            log.write_text(str(error) + "\n")
            code = 127
        entry.update(status="passed" if code == 0 else "failed", exit_code=code,
                     elapsed_seconds=round(time.monotonic() - begin, 3), log_sha256=sha256(log))
        failed = failed or code != 0
        save()
        # Formatting is preparation: do not run tests on a partially prepared tree.
        if name.startswith("format-") and code:
            break
    report["source_sha256_after"] = source_digest()
    report["status"] = "failed" if failed else "completed"
    save()
    print(f"\nReport: {report_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
