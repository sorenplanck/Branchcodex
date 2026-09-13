#!/usr/bin/env python3
"""Run explicitly selected real-daemon scenarios serially with fail-closed evidence.

Linux-only: a private session plus child-subreaper ownership also catches
orphaned descendants that create another process group/session. No global
process-name matching or signals to unverified numeric PIDs are used.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


PREFIX = ("production_contracts_bootstrap::producer_v13::native_ceremony_tests::"
          "xmr_coldstart_v23::daemon_scenario_v23::")
SCENARIOS = (
    "native_real_daemon_two_claims_survive_original_store_reopen_v23",
    "native_real_daemon_dom_compensation_without_counterparty_v23",
    "native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23",
)
LOG_LIMIT = 64 * 1024 * 1024
ARCHIVE_LIMIT = 256 * 1024 * 1024
RESULT = re.compile(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$", re.MULTILINE)
RUN_COUNT = re.compile(r"^running (\d+) tests?\s*$", re.MULTILINE)
TEST_START = re.compile(r"^test ([A-Za-z0-9_:]+) \.\.\.(?: |$)", re.MULTILINE)
DEPENDENCIES = (
    "DOM_INTEROP_REAL_BINARY_V23",
    "DOM_XMR_REAL_SIDECAR_V23",
    "DOM_XMR_OFFLINE_FUNDING_HELPER_V23",
)
CANCELLED = False


def private_synthetic_tmp():
    """Allocate a short private fixture root without traversing shared /tmp.

    The native sidecar intentionally rejects a writable ancestor such as
    /tmp.  Validate the complete HOME ancestry before creating our owned,
    reusable base and validate the new case directory before handing it to a
    child process.
    """
    home = Path.home()
    if not home.is_absolute() or home.resolve() != home:
        raise ValueError("canonical home required for the private fixture base")
    root_owner = Path("/").lstat().st_uid
    chain = (home, *home.parents)
    for ancestor in chain:
        metadata = ancestor.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or ancestor.resolve() != ancestor:
            raise ValueError("fixture ancestor must be a canonical directory")
        if metadata.st_uid not in (root_owner, os.getuid()) or metadata.st_mode & 0o022:
            raise ValueError("fixture ancestor ownership or write scope is unsafe")
    home_metadata = home.lstat()
    if home_metadata.st_uid != os.getuid():
        raise ValueError("fixture home is not owned by the current user")
    base = home / ".dx-v23"
    base.mkdir(mode=0o700, exist_ok=True)
    base_metadata = base.lstat()
    if (not stat.S_ISDIR(base_metadata.st_mode)
            or base_metadata.st_uid != os.getuid()
            or base_metadata.st_mode & 0o077
            or base.resolve() != base):
        raise ValueError("fixture base is not an original private directory")
    # Leave room in sockaddr_un for actor, sidecar and socket suffixes.
    if len(os.fsencode(base / "dx-00000000")) > 48:
        raise ValueError("private fixture base exceeds the native UDS path budget")
    path = Path(tempfile.mkdtemp(prefix="dx-", dir=base))
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077 or path.resolve() != path):
        raise ValueError("private case allocation ownership or mode refused")
    return path


def interrupted(signum, _frame):
    global CANCELLED
    CANCELLED = True
    raise InterruptedError(f"runner received signal {signum}")


def command(name):
    if name not in SCENARIOS:
        raise ValueError("unknown real-daemon scenario")
    return ["cargo", "test", "--locked", "-p", "dom-interopd",
            "--no-default-features", "--features", "production", "--lib",
            "--profile", "crypto-test", PREFIX + name, "--", "--ignored",
            "--exact", "--nocapture", "--test-threads=1", "--color", "never"]



def start_test_command_v24(identifier, *, cwd, env, stdout):
    """Closed literal argv dispatch, independently checked against the report.

    These deliberate literals keep the automation guard's no-dynamic-process
    boundary intact. A new selection or changed command must be reviewed here;
    changing the report/allowlist alone cannot execute an unreviewed command.
    No shell or caller-selected executable is accepted.
    """
    expected = command(identifier)
    if identifier == "native_real_daemon_two_claims_survive_original_store_reopen_v23":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_two_claims_survive_original_store_reopen_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_two_claims_survive_original_store_reopen_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native_real_daemon_dom_compensation_without_counterparty_v23":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_dom_compensation_without_counterparty_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_dom_compensation_without_counterparty_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_startup_v23::v23_dom_and_xmr_only_pair_starts_and_holds_with_no_foreign_family_resource":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_dom_and_xmr_only_pair_starts_and_holds_with_no_foreign_family_resource","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_dom_and_xmr_only_pair_starts_and_holds_with_no_foreign_family_resource","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_startup_v23::v23_live_state_directory_refuses_a_second_owner_in_either_mode":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_live_state_directory_refuses_a_second_owner_in_either_mode","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_live_state_directory_refuses_a_second_owner_in_either_mode","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_startup_v23::v23_stopped_state_directory_reopens_but_refuses_a_second_creation":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_stopped_state_directory_reopens_but_refuses_a_second_creation","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_startup_v23::v23_stopped_state_directory_reopens_but_refuses_a_second_creation","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_funding_v23::v23_route_evidence_persists_across_a_clean_shutdown_and_reopen":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_funding_v23::v23_route_evidence_persists_across_a_clean_shutdown_and_reopen","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_funding_v23::v23_route_evidence_persists_across_a_clean_shutdown_and_reopen","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_funding_v23::v23_route_evidence_survives_an_uncontrolled_crash_of_both_daemons":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_funding_v23::v23_route_evidence_survives_an_uncontrolled_crash_of_both_daemons","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_funding_v23::v23_route_evidence_survives_an_uncontrolled_crash_of_both_daemons","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_refund_v23::v23_second_actor_survives_and_restarts_with_the_first_unavailable":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_second_actor_survives_and_restarts_with_the_first_unavailable","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_second_actor_survives_and_restarts_with_the_first_unavailable","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_refund_v23::v23_first_actor_survives_and_restarts_with_the_second_unavailable":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_first_actor_survives_and_restarts_with_the_second_unavailable","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_first_actor_survives_and_restarts_with_the_second_unavailable","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_refund_v23::v23_survivor_reopens_repeatedly_with_a_permanently_absent_counterparty":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_survivor_reopens_repeatedly_with_a_permanently_absent_counterparty","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_refund_v23::v23_survivor_reopens_repeatedly_with_a_permanently_absent_counterparty","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_custody_v23::v23_custody_stores_survive_repeated_uncontrolled_restarts_on_both_sides":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_custody_v23::v23_custody_stores_survive_repeated_uncontrolled_restarts_on_both_sides","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_custody_v23::v23_custody_stores_survive_repeated_uncontrolled_restarts_on_both_sides","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "live_custody_v23::v23_corrupted_manifest_or_leg_authority_is_refused_and_the_original_is_not":
        if expected != ["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_custody_v23::v23_corrupted_manifest_or_leg_authority_is_refused_and_the_original_is_not","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","-p","dom-interopd","--no-default-features","--features","production","--lib","--profile","crypto-test","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::live_route_v23::live_custody_v23::v23_corrupted_manifest_or_leg_authority_is_refused_and_the_original_is_not","--","--ignored","--exact","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    raise ValueError("unreviewed native test dispatch")


def write_result(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def fingerprint_executable(value):
    """Record actual executable bytes; never execute a claimed dependency."""
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("scenario executable path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o022 or not os.access(path, os.X_OK)
                or not 1 <= before.st_size <= 1024 * 1024 * 1024):
            raise ValueError("scenario executable ownership, mode or size refused")
        digest = hashlib.blake2b(digest_size=32)
        for chunk in iter(lambda: source.read(65_536), b""):
            digest.update(chunk)
        after = os.fstat(source.fileno())
    identity = lambda meta: (meta.st_dev, meta.st_ino, meta.st_size,
                             meta.st_mtime_ns, meta.st_ctime_ns)
    if identity(before) != identity(after):
        raise RuntimeError("scenario executable changed while fingerprinting")
    return {"path": str(path), "blake2b256": digest.hexdigest(),
            "bytes": before.st_size, "device": before.st_dev,
            "inode": before.st_ino, "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns}


def dependency_fingerprints(environment):
    """Bind results to the real daemon AND the sidecar implementing V24."""
    expected = environment.get("DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise ValueError("mandatory daemon BLAKE2b-256 fingerprint is malformed")
    result = {name: fingerprint_executable(environment[name]) for name in DEPENDENCIES}
    if result["DOM_INTEROP_REAL_BINARY_V23"]["blake2b256"] != expected.lower():
        raise ValueError("actual production daemon does not match its supplied fingerprint")
    return result


def transcript_evidence(name, returncode, transcript):
    """A passing nested helper cannot disguise Cargo's zero-test success.

    With --nocapture libtest prints the selected name before arbitrary test
    output; its final 'ok' may appear on a later line. Match the name/start and
    the unique one-test summary independently, without relying on that layout.
    """
    if name not in SCENARIOS:
        raise ValueError("unknown real-daemon scenario")
    summaries = len(RESULT.findall(transcript))
    names = TEST_START.findall(transcript)
    counts = [int(count) for count in RUN_COUNT.findall(transcript)]
    expected = PREFIX + name
    passed = returncode == 0 and summaries == 1 and names == [expected] and counts == [1]
    return {"status": "passed" if passed else "failed",
            "exact_one_pass_summary_count": summaries,
            "executed_test_names": names, "libtest_run_counts": counts}


def record_fixture_evidence(result, archive):
    """A passing transcript cannot stand in for the original replay journals."""
    result["fixture_archive"] = archive
    if result["status"] == "passed" and archive is None:
        result["status"] = "failed"
        result["evidence_error"] = "successful scenario retained no original synthetic fixture archive"


def processes():
    """pid -> (parent, session, start ticks, state), parsed after comm's last ')'."""
    result = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            raw = (path / "stat").read_text()
            fields = raw[raw.rindex(")") + 2:].split()
            result[int(path.name)] = (int(fields[1]), int(fields[3]),
                                      int(fields[19]), fields[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


class OwnedProcesses:
    def __init__(self, session):
        self.session = session
        self.known = set()

    def snapshot(self):
        table = processes()
        # We are a dedicated single-campaign subreaper: our direct children
        # include adopted descendants, even after an unobserved setsid/fork.
        owned = {pid for pid, info in table.items()
                 if info[0] == os.getpid() or info[1] == self.session
                 or (pid, info[2]) in self.known}
        while True:
            children = {pid for pid, info in table.items() if info[0] in owned}
            expanded = owned | children
            if expanded == owned:
                break
            owned = expanded
        self.known.update((pid, table[pid][2]) for pid in owned)
        return {pid: table[pid] for pid in owned}

    @staticmethod
    def send(pid, expected, sig):
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            current = processes().get(pid)
            if current is not None and current[2] == expected[2]:
                signal.pidfd_send_signal(descriptor, sig)
        except ProcessLookupError:
            pass
        finally:
            os.close(descriptor)

    def cleanup(self, leader):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            leader.poll()  # Reap Popen's child before handling adopted orphans.
            owned = self.snapshot()
            if not owned:
                # A second empty scan closes the exit/reparent observation gap.
                time.sleep(0.05)
                if not self.snapshot():
                    return leader.returncode is not None
                continue
            # Freeze known writers/forkers before killing. Repeated scans pick
            # up children forked during the first snapshot and adopted orphans.
            for pid, info in owned.items():
                if info[3] != "Z":
                    self.send(pid, info, signal.SIGSTOP)
            for pid, info in self.snapshot().items():
                if info[3] != "Z":
                    self.send(pid, info, signal.SIGKILL)
                elif pid != leader.pid and info[0] == os.getpid():
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
            time.sleep(0.1)
        return False


def preserve_fixture(case, root):
    """Keep private modes in a tar; never follow symlinks or archive host files."""
    entries = []
    total = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            meta = path.lstat()
            if not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode)
                    or stat.S_ISLNK(meta.st_mode)):
                continue  # Dead Unix sockets have no replayable file contents.
            total += meta.st_size
            entries.append(path)
            if total > ARCHIVE_LIMIT or len(entries) > 100_000:
                raise RuntimeError("synthetic fixture archive limit exceeded")
    if not entries:
        return None
    archive = case / "synthetic-fixtures.tar.gz"
    with tarfile.open(archive, "w:gz", dereference=False) as output:
        for path in entries:
            output.add(path, arcname=str(path.relative_to(root)), recursive=False)
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return archive.name


def run_one(root, evidence, name, timeout):
    case = evidence / name
    case.mkdir(mode=0o700)
    # Unix-domain sockets have a small pathname limit. Do not put their
    # parent under the long artifact/scenario name or shared /tmp.
    synthetic_tmp = private_synthetic_tmp()
    result_path = case / "result.json"
    result = {"scenario": PREFIX + name, "status": "starting", "command": command(name),
              "cleanup_verified": False, "returncode": None,
              "synthetic_tmp": str(synthetic_tmp)}
    write_result(result_path, result)
    env = dict(os.environ, CARGO_TERM_COLOR="never", RUST_TEST_THREADS="1",
               CARGO_BUILD_JOBS="2", TMPDIR=str(synthetic_tmp),
               DOM_XMR_FAILED_FIXTURE_MARKER_V23=str(case / "failed-fixture-path.txt"))
    log = case / "test.log"
    start = time.monotonic()
    process = None
    tracker = None
    try:
        fingerprints = dependency_fingerprints(env)
        result["dependency_fingerprints"] = fingerprints
        with log.open("xb", buffering=0) as output, log.open("rb") as live:
            process = start_test_command_v24(name, cwd=root, env=env, stdout=output)
            tracker = OwnedProcesses(process.pid)
            result["status"] = "running"
            write_result(result_path, result)
            while process.poll() is None:
                tracker.snapshot()
                chunk = live.read(65_536)
                if chunk:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                if log.stat().st_size > LOG_LIMIT:
                    raise RuntimeError("scenario output exceeded 64 MiB")
                if time.monotonic() - start >= timeout:
                    raise TimeoutError("scenario wall-clock limit exceeded")
                time.sleep(0.1)
            result["returncode"] = process.returncode
            if log.stat().st_size > LOG_LIMIT:
                raise RuntimeError("scenario output exceeded 64 MiB")
            sys.stdout.buffer.write(live.read())
            sys.stdout.buffer.flush()
            transcript = log.read_text(errors="replace")
            result.update(transcript_evidence(name, process.returncode, transcript))
            result["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
            if dependency_fingerprints(env) != fingerprints:
                raise RuntimeError("scenario executable identity changed during execution")
            result["dependencies_unchanged"] = True
    except BaseException as error:
        result["status"] = "failed"
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            if tracker is not None and result["status"] == "passed":
                if any(info[3] != "Z" for info in tracker.snapshot().values()):
                    result["status"] = "failed"
                    result["error"] = "successful test left live descendant processes"
            result["cleanup_verified"] = process is None or tracker.cleanup(process)
            if process is not None:
                result["returncode"] = process.returncode
            if not result["cleanup_verified"]:
                result["status"] = "failed"
                result["cleanup_error"] = "descendants remain; next scenario MUST NOT start"
            else:
                record_fixture_evidence(result, preserve_fixture(case, synthetic_tmp))
                shutil.rmtree(synthetic_tmp)
                result["fixture_cleanup_verified"] = not synthetic_tmp.exists()
                if not result["fixture_cleanup_verified"]:
                    raise RuntimeError("private synthetic fixture directory remains")
        except BaseException as error:
            result["status"] = "failed"
            result["cleanup_verified"] = False
            result["cleanup_error"] = f"{type(error).__name__}: {error}"
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        write_result(result_path, result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=9_000)
    parser.add_argument("--scenario", action="append", choices=SCENARIOS, required=True)
    args = parser.parse_args()
    if len(set(args.scenario)) != len(args.scenario):
        parser.error("each scenario may be selected only once per campaign")
    if not 1 <= args.timeout_seconds <= 9_000:
        parser.error("timeout must be between 1 and 9000 seconds per scenario")
    root = Path(__file__).resolve().parents[1]
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    campaign = {"schema": "DOM-XMR-REAL-DAEMON-CAMPAIGN-V23", "status": "not-run",
                "results": [{"scenario": PREFIX + name, "status": "not-run"}
                            for name in args.scenario]}
    write_result(evidence / "campaign.json", campaign)
    try:
        if not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"):
            raise RuntimeError("Linux /proc, pidfd and child-subreaper are required")
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        for variable in ("DOM_INTEROP_REAL_BINARY_V23", "DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23",
                         "DOM_XMR_REAL_SIDECAR_V23", "DOM_XMR_OFFLINE_FUNDING_HELPER_V23"):
            if not os.environ.get(variable):
                raise RuntimeError(f"mandatory dependency missing: {variable}")
        campaign["daemon_blake2b256"] = os.environ["DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23"]
        campaign["git_sha"] = os.environ.get("GITHUB_SHA")
        campaign["lock_sha256"] = hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
        for index, name in enumerate(args.scenario):
            campaign["results"][index] = run_one(root, evidence, name, args.timeout_seconds)
            write_result(evidence / "campaign.json", campaign)
            if CANCELLED or not campaign["results"][index]["cleanup_verified"]:
                break
        campaign["status"] = ("passed" if all(item["status"] == "passed"
                                              for item in campaign["results"]) else "failed")
    except BaseException as error:
        campaign["status"] = "failed"
        campaign["error"] = f"{type(error).__name__}: {error}"
    write_result(evidence / "campaign.json", campaign)
    return 0 if campaign["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
