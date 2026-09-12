import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_v13 as bootstrap


def encoded(fields, family=6):
    body = (f"DOM-INTEROPD-BOOTSTRAP-V{family}\n" + "".join(k + "=" + v + "\n" for k, v in fields.items())).encode()
    return body + b"config_digest=" + hashlib.blake2b(bootstrap.DOMAIN + body, digest_size=32).hexdigest().encode() + b"\nend=1\n"


def artifact():
    data = bytearray(2538)
    data[:12] = b"DOMCTC1\0\0\x01\0\0"
    data[1450:1462] = b"DOMCTR1\0\0\x01\0\0"
    data[1462:1494] = hashlib.blake2b(b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-COMMIT/V1\0" + data[:1194], digest_size=32).digest()
    return bytes(data)  # Deliberately unsigned: this helper grants no authority.


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.fields = {"mode": "create", "registry_minimum_epoch": "7"}
        for i, key in enumerate(("network_id", "route_id", "registry_authority_set_digest", "registry_manifest_digest",
                                 "upstream_terms_digest", "downstream_terms_digest", "relay_binding_digest",
                                 "contracts_bootstrap_commit_digest", "contracts_bootstrap_reveal_digest")):
            self.fields[key] = bytes([i+1]*32).hex()
        for name in ("registry_authorities", "registry_store", "relay_roster", "contracts_transport_identity_store",
                     "contracts_budget_policy", "upstream_terms", "downstream_terms"):
            self.fields["path_" + name] = name + ".bin"
            (self.root / (name + ".bin")).write_bytes(b"public fixture")
        self.fields["path_contracts_bootstrap"] = "old.bin"

    def test_plan_extracts_only_selected_common_inputs(self):
        plan = bootstrap.make_plan(encoded(self.fields), self.root, "ab"*32)
        self.assertEqual(plan["schema"], 13)
        self.assertEqual(plan["local_participant_id"], [171]*32)
        self.assertEqual(plan["minimum_registry_epoch"], 7)
        self.assertEqual(plan["terms_files"], [str(self.root / (p + "_terms.bin")) for p in ("upstream", "downstream")])
        self.assertNotIn("btc", repr(plan).lower())

    def test_universal_wrapper_extracts_same_plan(self):
        common = encoded(self.fields)
        wrapper = encoded({"mode": "create", "common_v6": common.hex(), "universal": "7b7d"}, 11)
        self.assertEqual(bootstrap.make_plan(common, self.root, "ab"*32), bootstrap.make_plan(wrapper, self.root, "ab"*32))

    def test_bad_config_digest_and_duplicate_keys_refused(self):
        with self.assertRaises(ValueError):
            bootstrap.parse_config(encoded(self.fields).replace(b"registry_minimum_epoch=7", b"registry_minimum_epoch=8"))
        value = encoded(self.fields).replace(b"mode=create\n", b"mode=create\nmode=create\n")
        with self.assertRaises(ValueError):
            bootstrap.parse_config(value)

    def test_wrong_universal_mode_or_nested_family_refused(self):
        for mode, common in [("reopen_existing", encoded(self.fields)), ("create", encoded(self.fields, 5))]:
            with self.assertRaises(ValueError):
                bootstrap.common_config(encoded({"mode": mode, "common_v6": common.hex(), "universal": "7b7d"}, 11))

    def test_relative_escape_and_symlink_refused(self):
        for reference in ("../outside", "/tmp/outside", "./inside", "bad//name"):
            fields = {**self.fields, "path_registry_store": reference}
            with self.assertRaises(ValueError):
                bootstrap.make_plan(encoded(fields), self.root, "ab"*32)
        (self.root / "alias").symlink_to(self.root / "registry_store.bin")
        with self.assertRaises(ValueError):
            bootstrap.resolve_reference(self.root, "alias")

    def test_empty_zero_uppercase_and_overflow_pins_refused(self):
        for participant in ("", "00"*32, "AB"*32, "ab"*31):
            with self.assertRaises(ValueError):
                bootstrap.make_plan(encoded(self.fields), self.root, participant)
        with self.assertRaises(ValueError):
            bootstrap.make_plan(encoded({**self.fields, "registry_minimum_epoch": str(2**64)}), self.root, "ab"*32)

    def test_seal_preserves_every_nonbootstrap_field_and_mode(self):
        for mode in ("create", "reopen_existing"):
            source = encoded({**self.fields, "mode": mode})
            result = bootstrap.seal_config(source, artifact(), "ceremony/" + bootstrap.ARTIFACT)
            _, fields = bootstrap.parse_config(result)
            for key, value in bootstrap.common_config(source).items():
                if key not in ("path_contracts_bootstrap", "contracts_bootstrap_commit_digest", "contracts_bootstrap_reveal_digest", "config_digest"):
                    self.assertEqual(fields[key], value)
            self.assertEqual(fields["path_contracts_bootstrap"], "ceremony/" + bootstrap.ARTIFACT)

    def test_seal_universal_preserves_external_resources_exactly(self):
        wrapper = encoded({"mode": "create", "common_v6": encoded(self.fields).hex(), "universal": "00ab1234"}, 11)
        _, result = bootstrap.parse_config(bootstrap.seal_config(wrapper, artifact(), bootstrap.ARTIFACT))
        self.assertEqual(result["universal"], "00ab1234")
        self.assertEqual(bootstrap.common_config(bytes.fromhex(result["common_v6"]))["path_contracts_bootstrap"], bootstrap.ARTIFACT)

    def test_artifact_missing_changed_stage_or_trailing_bytes_refused(self):
        changed = bytearray(artifact()); changed[80] ^= 1
        for data in (b"", artifact() + b"x", changed):
            with self.assertRaises(ValueError):
                bootstrap.artifact_pins(data)
        with self.assertRaises(ValueError):
            bootstrap.seal_config(encoded(self.fields), artifact(), "legacy-name.bin")

    def test_new_output_never_overwrites_existing_or_linked_file(self):
        path = self.root / "output.json"
        bootstrap.write_new(path, b"original")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(bootstrap.read_owned(path), b"original")
        with self.assertRaises(FileExistsError):
            bootstrap.write_new(path, b"replacement")
        os.link(path, self.root / "hardlink")
        with self.assertRaises(ValueError):
            bootstrap.read_owned(path)
        self.assertEqual(path.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
