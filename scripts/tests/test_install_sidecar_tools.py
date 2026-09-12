"""Lightweight installer isolation checks; no Cargo or network access."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "install-sidecar-into-eigenwallet.py"
SPEC = importlib.util.spec_from_file_location("install_sidecar_tools", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

MANIFEST = """[workspace]
resolver = "2"
members = [
  "libp2p-rendezvous-node",
  "monero-wallet-ng",
  "dom-xmr-sidecar",
  "xmr-key-image-proof",
  "xmr-raw-tx-verify",
]

[workspace.dependencies]
monero-oxide = { git = "https://example.invalid/pinned-sdk" }
arti-client = { git = "https://example.invalid/not-a-tool-dependency" }
[patch.crates-io]
crunchy = { git = "https://example.invalid/unchanged", rev = "fixed" }
[profile.release]
lto = "fat"
"""

class OfflineToolWorkspaceTests(unittest.TestCase):
    def test_only_members_change_and_sources_and_lock_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in installer.TOOL_MEMBERS:
                directory = root / name
                directory.mkdir()
                (directory / "Cargo.toml").write_text('[package]\nname = "' + name + '"\n')
            cargo = root / "Cargo.toml"
            cargo.write_text(MANIFEST)
            lock = root / "Cargo.lock"
            lock.write_bytes(b"exact pinned dependency lock")
            before_files = {str(path.relative_to(root)): path.read_bytes()
                            for path in root.rglob("*") if path.is_file()}
            installer.restrict_to_offline_tools(root)
            after = tomllib.loads(cargo.read_text())
            before = tomllib.loads(MANIFEST)
            self.assertEqual(after["workspace"]["members"], list(installer.TOOL_MEMBERS))
            before["workspace"]["members"] = list(installer.TOOL_MEMBERS)
            self.assertEqual(after, before)
            for name, data in before_files.items():
                if name != "Cargo.toml":
                    self.assertEqual((root / name).read_bytes(), data)
            once = cargo.read_bytes()
            installer.restrict_to_offline_tools(root)
            self.assertEqual(cargo.read_bytes(), once)

    def test_missing_package_refuses_without_rewriting_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cargo = root / "Cargo.toml"
            cargo.write_text(MANIFEST)
            with self.assertRaises(SystemExit):
                installer.restrict_to_offline_tools(root)
            self.assertEqual(cargo.read_text(), MANIFEST)

    def test_ambiguous_default_members_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in installer.TOOL_MEMBERS:
                (root / name).mkdir()
                (root / name / "Cargo.toml").write_text("")
            cargo = root / "Cargo.toml"
            original = MANIFEST.replace('resolver = "2"', 'resolver = "2"\ndefault-members = ["libp2p-rendezvous-node"]')
            cargo.write_text(original)
            with self.assertRaises(SystemExit):
                installer.restrict_to_offline_tools(root)
            self.assertEqual(cargo.read_text(), original)

    def test_ci_selects_tool_workspace_before_cache_metadata_and_build(self):
        action = (SCRIPT.parents[1] / ".github/actions/xmr-test-tools/action.yml").read_text()
        self.assertIn('install-sidecar-into-eigenwallet.py "$XMR_TEST_WORKSPACE" --tools-only', action)
        self.assertLess(action.index("--tools-only"), action.index("Restore GPL crypto compilation"))
        self.assertLess(action.index("Restore GPL crypto compilation"), action.index("Build pinned offline tools"))

if __name__ == "__main__":
    unittest.main()
