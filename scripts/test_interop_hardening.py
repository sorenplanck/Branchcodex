#!/usr/bin/env python3
"""Run real repository test commands and retain observed outcomes, never a security score."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
FULL_SHARDS = (
    "protocol", "production-native", "production-native-funding", "production-native-claim",
    "production-native-wallet-reopen", "production-native-templates",
    "production-lib", "production-integration", "live",
)
NATIVE_TEST_PREFIX = ("production_contracts_bootstrap::producer_v13::native_ceremony_tests::"
                      "xmr_graph_wallet_tests")
NATIVE_FUNDING_TEST = (NATIVE_TEST_PREFIX +
                       "::v23_native_two_leg_templates_custody_ready_and_bounded_funding")
NATIVE_CLAIM_TEST = (NATIVE_TEST_PREFIX +
                     "::v23_native_claim_six_messages_and_presignature_with_real_output_scan")
NATIVE_WALLET_REOPEN_TEST = (NATIVE_TEST_PREFIX +
    "::v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses")
NATIVE_TEMPLATES_TEST = (NATIVE_TEST_PREFIX +
    "::v23_two_wallets_and_native_cd_proofs_form_identical_graph_templates")
NATIVE_EXACT_TESTS = {
    "production-native-funding": NATIVE_FUNDING_TEST,
    "production-native-claim": NATIVE_CLAIM_TEST,
    "production-native-wallet-reopen": NATIVE_WALLET_REOPEN_TEST,
    "production-native-templates": NATIVE_TEMPLATES_TEST,
}
NATIVE_EXACT_SHARDS = frozenset(NATIVE_EXACT_TESTS)
PRODUCTION_INTEGRATION_TARGETS = (
    "admission", "admission_v2", "driver", "f6_artifact_cli", "planning_cli",
    "production_time_guard", "relay_worker", "route_services_cli", "supervisor",
    "xmr_enrollment_cli", "xmr_leg_cli",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_native_shard_error(name, log):
    if name not in NATIVE_EXACT_SHARDS:
        return None
    summary = log.read_text(errors="replace")
    if re.search(r"(?m)^test result: ok\. 1 passed; 0 failed;", summary):
        return None
    return "exact native shard did not report exactly one passed test"


def source_digest():
    # Include staged, unstaged and new source files, excluding generated evidence.
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    paths = sorted(set(os.fsdecode(p) for p in raw.split(b"\0") if p))
    digest = hashlib.sha256()
    for name in paths:
        if name.startswith(("artifacts/", ".ci-eigenwallet/", ".ci-eigenwallet.partial-")):
            continue
        path = ROOT / name
        if path.is_file():
            digest.update(name.encode() + b"\0" + bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def production_environment_v24(env):
    """Scope an existing private fixture root to the production child only.

    Never allocate, repair permissions or fall back to shared /tmp. Keeping
    this out of the parent environment preserves the cleanup contracts of the
    Bitcoin/Forge scripts and every other independent command.
    """
    raw = env.get("DOM_XMR_PRIVATE_TMP_V23", "")
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise PermissionError("production requires its private fixture root")
    try:
        home = Path.home()
        base = home / ".dx-v23"
        directory = Path(raw)
        if (not home.is_absolute() or home.resolve(strict=True) != home
                or not directory.is_absolute() or str(directory) != raw
                or directory.parent != base or not directory.name.startswith("dx-")
                or len(directory.name) <= 3):
            raise PermissionError("production private fixture scope is invalid")
        owner = os.getuid()
        root_owner = Path("/").lstat().st_uid
        for ancestor in (directory, *directory.parents):
            metadata = ancestor.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or ancestor.resolve(strict=True) != ancestor
                    or metadata.st_uid not in (owner, root_owner)
                    or metadata.st_mode & 0o022):
                raise PermissionError("production fixture ancestry is unsafe")
            if ancestor in (directory, base):
                if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise PermissionError("production fixture must be an owned private directory")
            if ancestor == home and metadata.st_uid != owner:
                raise PermissionError("production fixture home has another owner")
    except (ValueError, RuntimeError) as error:
        raise PermissionError("production private fixture path is invalid") from error
    return {**env, "TMPDIR": raw}


def commands(mode, evidence_directory, full_shard="all"):
    if full_shard not in ("all", *FULL_SHARDS) or (mode != "full" and full_shard != "all"):
        raise ValueError("full shard requires full mode and a closed selection")
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
    # The CI preflight already builds this workspace in crypto-test. Keep the
    # component commands in that profile so compatible Cargo units can be
    # reused instead of compiling a second dev tree. This retains debug
    # assertions/overflow checks and executes every original target and oracle.
    # The separate Solana program workspace has no such profile and is unchanged.
    monero = ("monero-rpc-and-actuator-v5", ["cargo", "test", "--locked", "--no-fail-fast", "--profile", "crypto-test", "-p",
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
        ("bitcoin", ["cargo", "test", "--locked", "--no-fail-fast", "--profile", "crypto-test", "-p", "btc-crypto", "-p", "adapter-btc", "-p", "btc-actuator"],
         {**driver_env, "DOM_INTEROP_V3_PUBLIC_FIXTURE": str(evidence_directory / "rust-participant-round-v3.json")}),
        driver_verification,
        ("rust-participant-independent-verification", [sys.executable, "scripts/bitcoin_participant_oracle.py",
         str(evidence_directory / "rust-participant-round-v3.json")], {}),
        ("solana-adapters", ["cargo", "test", "--locked", "--no-fail-fast", "--profile", "crypto-test", "-p", "kaystra-core", "-p", "solana-kaystra-source", "-p", "solana-escrow-wire", "-p", "solana-program-client", "-p", "solana-observer", "-p", "solana-evidence", "-p", "solana-observation-store", "-p", "solana-observer-pump"], {}),
        ("solana-program-host", ["cargo", "test", "--manifest-path", "programs/dom-solana-escrow/Cargo.toml", "--locked", "--no-fail-fast"], {}),
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
        if full_shard != "all":
            return full_shard_commands(specs, full_shard, trace_env, production_env)
    return specs


def full_shard_commands(specs, shard, trace_env, production_env):
    """Partition existing checks; each oracle stays with its actual producer."""
    by_name = {name: (name, command, env) for name, command, env in specs}
    if shard == "protocol":
        return [by_name[name] for name in (
            "independent-oracles", "workspace-lock", "bitcoin",
            "rust-driver-final-signature-verification", "rust-participant-independent-verification",
            "solana-adapters", "solana-program-host", "monero-rpc-and-actuator-v5",
        )]
    if shard == "production-native":
        return [(shard, native_shard_command(shard), {})]
    if shard in NATIVE_EXACT_SHARDS:
        return [(shard, native_shard_command(shard), {})]
    if shard == "production-lib":
        return [(shard, ["cargo", "test", "-p", "dom-interopd", "--no-default-features",
            "--features", "production", "--lib", "--locked", "--profile", "crypto-test",
            "--no-fail-fast", "--", "--nocapture", "--test-threads=1", "--skip", NATIVE_TEST_PREFIX],
            trace_env), by_name["rust-route-independent-verification"]]
    if shard == "production-integration":
        # `--tests` also selects library unit tests. Explicit integration and
        # binary targets are the disjoint complement of the two --lib shards.
        # Avoid glob selection of targets whose required-features are absent.
        # The preflight contract compares this list with all tests/*.rs and
        # verifies each excluded target's exact Cargo feature gate.
        return [(shard, ["cargo", "test", "-p", "dom-interopd", "--no-default-features",
            "--features", "production",
            *(arg for target in PRODUCTION_INTEGRATION_TARGETS for arg in ("--test", target)),
            "--bins", "--locked", "--profile", "crypto-test",
            "--no-fail-fast", "--", "--nocapture", "--test-threads=1"],
            {"DOM_INTEROP_V5_TIME_FIXTURE": production_env["DOM_INTEROP_V5_TIME_FIXTURE"]}),
            by_name["rust-time-independent-verification"]]
    if shard == "live":
        return [by_name[name] for name in ("bitcoin-regtest", "evm-deep", "evm-anvil")]
    raise ValueError("unknown full shard")


def native_shard_command(shard):
    command = ["cargo", "test", "-p", "dom-interopd", "--no-default-features",
               "--features", "production", "--lib", "--locked", "--profile", "crypto-test",
               "--no-fail-fast"]
    if shard == "production-native":
        return command + [NATIVE_TEST_PREFIX, "--", "--nocapture", "--test-threads=1",
                          *(arg for name in NATIVE_EXACT_TESTS.values() for arg in ("--skip", name))]
    selected = NATIVE_EXACT_TESTS.get(shard)
    if selected is None:
        raise ValueError("unknown native shard")
    return command + [selected, "--", "--exact", "--nocapture", "--test-threads=1"]


def required_tools(mode, full_shard="all"):
    required = ["git"]
    if mode != "offline":
        required += ["cargo", "rustc", "cc", "clang", "cmake", "pkg-config"]
    if mode == "full" and full_shard in ("all", "protocol", "live"):
        required += ["bitcoind", "bitcoin-cli"]
    if mode == "full" and full_shard in ("all", "live"):
        required += ["forge", "anvil", "curl"]
    return required


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
        return subprocess.Popen(['cargo', 'test', '--locked', '--no-fail-fast', '--profile', 'crypto-test', '-p', 'xmr-rpc-broadcast-blocking', '-p', 'xmr-actuator'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--tests', '--locked', '--profile', 'crypto-test', '--no-fail-fast', '--', '--nocapture', '--test-threads=1'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-native':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--locked', '--profile', 'crypto-test', '--no-fail-fast', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests', '--', '--nocapture', '--test-threads=1', '--skip', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_native_two_leg_templates_custody_ready_and_bounded_funding', '--skip', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_native_claim_six_messages_and_presignature_with_real_output_scan', '--skip', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses', '--skip', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_two_wallets_and_native_cd_proofs_form_identical_graph_templates'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-native-funding':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--locked', '--profile', 'crypto-test', '--no-fail-fast', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_native_two_leg_templates_custody_ready_and_bounded_funding', '--', '--exact', '--nocapture', '--test-threads=1'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-native-claim':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--locked', '--profile', 'crypto-test', '--no-fail-fast', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_native_claim_six_messages_and_presignature_with_real_output_scan', '--', '--exact', '--nocapture', '--test-threads=1'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-native-wallet-reopen':
        return subprocess.Popen(["cargo","test","-p","dom-interopd","--no-default-features","--features","production","--lib","--locked","--profile","crypto-test","--no-fail-fast","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses","--","--exact","--nocapture","--test-threads=1"], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-native-templates':
        return subprocess.Popen(["cargo","test","-p","dom-interopd","--no-default-features","--features","production","--lib","--locked","--profile","crypto-test","--no-fail-fast","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::v23_two_wallets_and_native_cd_proofs_form_identical_graph_templates","--","--exact","--nocapture","--test-threads=1"], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-lib':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--lib', '--locked', '--profile', 'crypto-test', '--no-fail-fast', '--', '--nocapture', '--test-threads=1', '--skip', 'production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'production-integration':
        return subprocess.Popen(['cargo', 'test', '-p', 'dom-interopd', '--no-default-features', '--features', 'production', '--test', 'admission', '--test', 'admission_v2', '--test', 'driver', '--test', 'f6_artifact_cli', '--test', 'planning_cli', '--test', 'production_time_guard', '--test', 'relay_worker', '--test', 'route_services_cli', '--test', 'supervisor', '--test', 'xmr_enrollment_cli', '--test', 'xmr_leg_cli', '--bins', '--locked', '--profile', 'crypto-test', '--no-fail-fast', '--', '--nocapture', '--test-threads=1'], cwd=ROOT, env=env,
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
        return subprocess.Popen(['cargo', 'test', '--locked', '--no-fail-fast', '--profile', 'crypto-test', '-p', 'btc-crypto', '-p', 'adapter-btc', '-p', 'btc-actuator'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'rust-participant-independent-verification':
        # Fixed module import locations; an evidence file cannot choose code.
        env = {**env, "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "scripts")))}
        return subprocess.Popen(['python3', '-m', 'scripts.bitcoin_participant_oracle', 'rust-participant-round-v3.json'], cwd=evidence_directory, env=env, executable=sys.executable,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'solana-adapters':
        return subprocess.Popen(['cargo', 'test', '--locked', '--no-fail-fast', '--profile', 'crypto-test', '-p', 'kaystra-core', '-p', 'solana-kaystra-source', '-p', 'solana-escrow-wire', '-p', 'solana-program-client', '-p', 'solana-observer', '-p', 'solana-evidence', '-p', 'solana-observation-store', '-p', 'solana-observer-pump'], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if name == 'solana-program-host':
        return subprocess.Popen(['cargo', 'test', '--manifest-path', 'programs/dom-solana-escrow/Cargo.toml', '--locked', '--no-fail-fast'], cwd=ROOT, env=env,
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
    parser.add_argument("--full-shard", choices=("all", *FULL_SHARDS), default=None,
                        help="full-mode partition; default all retains the complete serial campaign")
    parser.add_argument("--format", action="store_true", help="run rustfmt before testing; records the resulting source digest")
    args = parser.parse_args()
    if args.mode == "offline" and args.format:
        parser.error("--format requires a Rust test mode")
    if args.full_shard is not None and args.mode != "full":
        parser.error("--full-shard requires --mode full")
    full_shard = args.full_shard or "all"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_root = ROOT / "artifacts" / "interop-hardening"
    evidence_root.mkdir(parents=True, exist_ok=True)
    # Separate PID namespaces may reuse pid/time. Exclusive random suffixes
    # keep concurrent runs from colliding or mixing their evidence.
    out = Path(tempfile.mkdtemp(prefix=f"{stamp}-{args.mode}-{full_shard}-{os.getpid()}-", dir=evidence_root))
    report = {
        "schema_version": 1, "scope": "repository-test-commands",
        "mode": args.mode, "full_shard": full_shard, "started_utc": stamp, "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
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
    if full_shard != "all":
        report["limits"].append(
            "This report covers only the selected full-mode shard; the full campaign requires all nine shard outcomes.")
    report_path = out / "report.json"

    def save():
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(report_path)

    save()
    required = required_tools(args.mode, full_shard)
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        report.update(status="blocked", missing_tools=missing)
        save()
        print("Missing tools: " + ", ".join(missing), file=sys.stderr)
        print(f"Observed report: {report_path}")
        return 2
    specs = commands(args.mode, out, full_shard)
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
                if name == "production" or name.startswith("production-"):
                    env = production_environment_v24(env)
                    entry["private_fixture_root"] = env["TMPDIR"]
                    save()
                process = start_test_command(name, env, out)
                entry["executed_command"] = process.args
                save()
                for line in iter(process.stdout.readline, b""):
                    stream.write(line)
                    stream.flush()
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                code = process.wait()
            if code == 0:
                validation_error = exact_native_shard_error(name, log)
                if validation_error:
                    with log.open("a") as stream:
                        stream.write(f"\nERROR: {validation_error}\n")
                    code = 3
                    entry["validation_error"] = validation_error
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
