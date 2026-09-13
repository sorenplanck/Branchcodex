"""Cheap path/AF_UNIX checks; no Cargo, helper executable or crypto graph."""
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_uds_preflight_v24 as preflight
from run_native_daemon_scenario_v23 import private_synthetic_tmp


class NativeUdsPreflightTests(unittest.TestCase):
    def setUp(self):
        self.root = private_synthetic_tmp()
        self.addCleanup(shutil.rmtree, self.root)
        self.env = {"DOM_XMR_PRIVATE_TMP_V23": str(self.root), "TMPDIR": "/tmp"}

    def test_actual_bind_connect_and_cleanup_do_not_change_parent_environment(self):
        original = dict(self.env)
        result = preflight.probe_private_uds_v24(self.env)
        self.assertEqual(self.env, original)
        self.assertEqual(result["private_fixture_root"], str(self.root))
        self.assertTrue(result["transport_roundtrip"])
        self.assertTrue(result["cleanup_verified"])
        self.assertGreater(result["socket_path_bytes"], len(os.fsencode(self.root)))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_shared_tmp_and_missing_scope_refuse_before_allocation_or_socket(self):
        for env in ({}, {"TMPDIR": str(self.root)}, {"DOM_XMR_PRIVATE_TMP_V23": "/tmp"}):
            with self.subTest(env=env), mock.patch.object(preflight.socket, "socket") as create_socket, \
                    mock.patch.object(preflight.tempfile, "TemporaryDirectory") as allocate:
                with self.assertRaises(PermissionError):
                    preflight.probe_private_uds_v24(env)
                create_socket.assert_not_called()
                allocate.assert_not_called()

    def test_permissive_root_and_symlink_refuse_before_bind(self):
        self.root.chmod(0o777)
        try:
            with mock.patch.object(preflight.socket, "socket") as create_socket:
                with self.assertRaises(PermissionError):
                    preflight.probe_private_uds_v24(self.env)
                create_socket.assert_not_called()
        finally:
            self.root.chmod(0o700)
        link = self.root.parent / (self.root.name + "-link")
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(PermissionError):
            preflight.probe_private_uds_v24({"DOM_XMR_PRIVATE_TMP_V23": str(link)})

    def test_bind_failure_is_not_success_and_removes_only_probe_directory(self):
        marker = self.root / "retained-owned-marker"
        marker.write_bytes(b"must remain")
        with mock.patch.object(preflight.socket, "socket") as create_socket:
            create_socket.return_value.__enter__.return_value.bind.side_effect = OSError("bind refused")
            with self.assertRaisesRegex(OSError, "bind refused"):
                preflight.probe_private_uds_v24(self.env)
        self.assertEqual(list(self.root.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"must remain")

    def test_failed_preflight_records_failure_and_never_replaces_evidence(self):
        output = self.root / "status.json"
        with mock.patch.dict(os.environ, {"DOM_XMR_PRIVATE_TMP_V23": "/tmp"}):
            self.assertEqual(preflight.main(["--result", str(output)]), 1)
            original = output.read_bytes()
            self.assertEqual(json.loads(original)["status"], "failed")
            with self.assertRaises(FileExistsError):
                preflight.main(["--result", str(output)])
            self.assertEqual(output.read_bytes(), original)

    def test_partial_transport_reads_are_accumulated_but_early_eof_is_refused(self):
        connection = mock.Mock()
        connection.recv.side_effect = [b"DOM", b"-", b"UDS!"]
        self.assertEqual(preflight.receive_exact_v24(connection, 8), b"DOM-UDS!")
        connection.recv.side_effect = [b"DOM", b""]
        with self.assertRaises(EOFError):
            preflight.receive_exact_v24(connection, 8)

    def test_action_runs_probe_before_cargo_and_requires_its_own_result(self):
        action = (Path(__file__).resolve().parents[2] / ".github/actions/xmr-test-tools/action.yml").read_text()
        marker = "Verify private UDS ancestry and actual socket readiness before compilation"
        self.assertLess(action.index(marker), action.index("Compile production library, CLI and integration targets"))
        step = action.split(marker, 1)[1].split("    - name:", 1)[0]
        self.assertIn("id: uds_preflight", step)
        self.assertIn("continue-on-error: true", step)
        self.assertIn("scripts/native_uds_preflight_v24.py", step)
        self.assertNotIn("cargo ", step)
        self.assertNotIn("TMPDIR=", step)
        summary = action.split("Report every native-tool verification failure", 1)[1]
        self.assertIn("if: always()", summary)
        self.assertIn("steps.uds_preflight.outcome", summary)
        self.assertIn('[[ "$UDS_PREFLIGHT" == success ]] || failed=1', summary)
        self.assertIn('[[ "$UDS_EVIDENCE" == success ]] || failed=1', summary)
        archive = action.split("Preserve private UDS readiness result", 1)[1].split("    - name:", 1)[0]
        self.assertIn("continue-on-error: true", archive)
        self.assertIn("id: uds_evidence", archive)
        self.assertIn('exit "$failed"', summary)
        for name in (
            "Verify Funding and Claim reservation audit purposes",
            "Verify public refund authentication and durable Ready recovery",
            "Verify scoped funding, custody and transport regressions",
            "Verify custody paths and real offline helper startup",
            "Verify XMR recovery participant ordering",
            "Verify offline operational artifact producers",
        ):
            step = action.split(name, 1)[1].split("    - name:", 1)[0]
            self.assertIn("TMPDIR: ${{ env.DOM_XMR_PRIVATE_TMP_V23 }}", step)
        # Never propagate this fixture choice into Bitcoin/Forge/installers.
        self.assertNotIn("TMPDIR=%s", action)


if __name__ == "__main__":
    unittest.main()
