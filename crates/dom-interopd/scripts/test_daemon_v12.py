#!/usr/bin/env python3
"""Validate the V12 candidate: native components, daemon build and artifact checks. Never executes a live swap."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = "crates/dom-interopd/scripts"


def source_digest():
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    digest = hashlib.sha256()
    for name in sorted(set(os.fsdecode(p) for p in paths.split(b"\0") if p)):
        path = ROOT / name
        if not name.startswith("artifacts/") and path.is_file():
            digest.update(name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Python verifier tests only; no Rust validation")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = ROOT / "artifacts" / "daemon-v12"
    evidence.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix=stamp + "-", dir=evidence))
    report = {"schema": 12, "status": "incomplete", "mode": "offline" if args.offline else "daemon",
              "source_sha256_before": source_digest() if shutil.which("git") else None,
              "checks": [], "chain_swaps_executed": 0,
              "all_sixteen_routes_operational": False,
              "limits": ["Passing this runner does not prove live chain swaps or 10/10 security.",
                         "Python-only mode cannot validate Rust code.",
                         "Rust signer/configuration oracles use public fixtures, not live chain swaps.",
                         "V4 selects the universal root; V3 preserves legacy recovery. Full route execution is not yet established.",
                         "V12 adds native DOM claim, generalized F7 and XMR recovery producers; complete startup/runtime integration remains incomplete.",
                         "A plain pre-signed compensation can be manually spent without XMR funding; daemon guards alone do not close that protocol risk.",
                         "DOM/XMR sweep and refund observation code do not establish a live, fully recovered atomic swap.",
                         "The adaptor refund must not disclose both pre-signature and final signature before its intended revelation."]}
    report_path = out / "report.json"

    def save():
        temporary = out / "report.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(report_path)

    save()
    required = ["git"] + ([] if args.offline else ["cargo", "rustc", "cc", "clang", "cmake", "pkg-config"])
    missing = [tool for tool in required if shutil.which(tool) is None]
    if importlib.util.find_spec("cryptography") is None:
        missing.append("Python cryptography (requirements-v7.txt)")
    if missing:
        report.update(status="blocked", missing_tools=missing)
        save()
        print("Pré-requisitos ausentes: " + ", ".join(missing))
        print("Relatório: " + str(report_path))
        return 2
    commands = [("layer-guards", [sys.executable, "scripts/guard_layer_policy.py"], {}),
                ("python-daemon-oracles", [sys.executable, "-m", "unittest", "discover", "-s", SCRIPTS + "/tests", "-v"], {}),
                ("python-repository-tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-v"], {})]
    if not args.offline:
        commands.extend([
            ("workspace-lock", ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], {}),
            ("rust-universal-config", ["cargo", "test", "--locked", "-p", "dom-interopd", "--no-default-features", "--features", "config-only", "--lib"], {}),
            ("rust-dom-refund-crypto", ["cargo", "test", "--locked", "-p", "dom-scriptless-crypto"], {}),
            ("rust-xmr-init-recovery", ["cargo", "test", "--locked", "-p", "xmr-dleq-nullifier-store", "-p", "xmr-refund-policy", "-p", "xmr-session-init", "-p", "xmr-runtime-wiring", "-p", "xmr-observer"], {}),
            ("rust-dom-observation", ["cargo", "test", "--locked", "-p", "adapter-dom-real"], {}),
            ("rust-xmr-components", ["cargo", "test", "--locked", "-p", "xmr-crypto", "-p", "xmr-dleq-sigma", "-p", "xmr-refund-adaptor", "-p", "xmr-secret-store", "-p", "xmr-raw-tx-verify", "-p", "xmr-actuator", "-p", "xmr-sidecar-auth"], {}),
            ("rust-daemon", ["cargo", "test", "--locked", "-p", "dom-interopd", "--no-default-features", "--features", "production", "--lib", "--tests"],
             {"DOM_INTEROP_V7_SOLANA_SIGNATURES": str(out / "rust-solana-signatures.json"),
              "DOM_INTEROP_V8_ROUTE_SERVICES": str(out / "rust-route-services.json")}),
            ("rust-python-signatures", [sys.executable, SCRIPTS + "/solana_signatures_v7.py", str(out / "rust-solana-signatures.json")], {}),
            ("rust-python-route-services", [sys.executable, SCRIPTS + "/route_services_v8.py", str(out / "rust-route-services.json")], {}),
            ("rust-xmr-rpc", ["cargo", "test", "--locked", "-p", "xmr-rpc-broadcast-blocking"], {}),
            ("rust-f7-authority", ["cargo", "test", "--locked", "-p", "f7-anchor-authority"], {}),
            ("rust-store", ["cargo", "test", "--locked", "-p", "dom-scriptless-store"], {}),
            ("rust-store-ancestry-fixtures", ["cargo", "test", "--locked", "-p", "dom-scriptless-store", "--features", "evidence-only", "--lib"], {}),
            ("rust-solana-native", ["cargo", "test", "--locked", "-p", "solana-rpc", "-p", "solana-actuator"], {}),
            ("rust-route-compensation", ["cargo", "test", "--locked", "-p", "route-executor", "--no-default-features", "--features", "production,native-xmr-compensation"], {}),
            ("rust-dom-wallet-vault", ["cargo", "test", "--locked", "-p", "dom-actuator", "-p", "dom-adaptor", "-p", "dom-vault"], {}),
            ("rust-bitcoin-participants", ["cargo", "test", "--locked", "-p", "btc-actuator"], {}),
            ("rust-xmr-sidecar", ["cargo", "test", "--locked", "-p", "xmr-live-sidecar-uds-client"], {}),
            ("release-daemon", ["cargo", "build", "--locked", "--release", "-p", "dom-interopd", "--no-default-features", "--features", "production", "--bin", "dom-interopd"], {}),
            ("artifact-self-check", ["cargo", "run", "--locked", "--release", "-p", "dom-interopd", "--no-default-features", "--features", "production", "--bin", "dom-interopd", "--", "self-check", "--json"], {}),
        ])
    for name, command, extra in commands:
        entry = {"id": name, "command": command, "status": "running", "log": name + ".log"}
        report["checks"].append(entry)
        save()
        print("Executando " + name, flush=True)
        begin = time.monotonic()
        log = out / entry["log"]
        code = 127
        try:
            with log.open("wb") as stream:
                # The child owns its complete log directly. Console forwarding
                # must not truncate evidence or affect a test's outcome.
                process = subprocess.Popen(command, cwd=ROOT, env={**os.environ, **extra, "CARGO_TERM_COLOR": "never"},
                                           stdout=stream, stderr=subprocess.STDOUT)
                code = process.wait()
            print(name + (": OK" if code == 0 else ": FALHOU") + " — " + str(log), flush=True)
        except OSError as error:
            log.write_text(str(error) + "\n")
        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            code = 130
        entry.update(status="passed" if code == 0 else "failed", exit_code=code,
                     elapsed_seconds=round(time.monotonic() - begin, 3), log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
        save()
        if code:
            break
    after = source_digest()
    report.update(status="passed" if report["checks"] and all(c["status"] == "passed" for c in report["checks"])
                  and after == report["source_sha256_before"] else "failed",
                  source_sha256_after=after, source_unchanged=after == report["source_sha256_before"])
    save()
    print("Relatório: " + str(report_path))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
