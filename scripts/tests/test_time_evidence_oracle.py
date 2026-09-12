"""Synthetic test-only signatures. Never use these fixed keys for funds."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_claim_oracle as crypto
import time_evidence_oracle as oracle
import publish_time_refresh as publisher
from test_bitcoin_participant_oracle import test_signature


def fixture(sequence=2, observed=1000):
    body = b"DOMRTEV2\0\2\0\0" + bytes([1])*32 + bytes([2])*32 + struct.pack(">QQQ", sequence, observed, observed+50)
    for role, clock in [(1,1),(2,2),(3,3)]:
        body += bytes([role,clock,0,0]) + bytes([role])*96 + struct.pack(">Q",100) + bytes([4])*64
        body += struct.pack(">QQQ",900,950,110) + bytes([5])*64
    assert len(body) == 880
    digest = hashlib.blake2b(oracle.DOMAIN + body, digest_size=32).digest()
    raw = b"DOMRTSE2\0\2\0\0" + struct.pack(">I",len(body)) + body + struct.pack(">H",2)
    keys = []
    for index, scalar in enumerate((3,5)):
        keys.append(crypto.multiply(scalar, crypto.G)[0].to_bytes(32,"big").hex())
        raw += struct.pack(">H",index) + test_signature(digest,scalar)
    pins = dict(public_keys=keys, threshold=2, minimum_sequence=1,
                policy_digest="01"*32, route_scope_digest="02"*32)
    return raw,pins


class TimeEvidenceOracleTests(unittest.TestCase):
    def test_valid_synthetic_threshold_signature(self):
        raw,pins=fixture()
        result=oracle.verify(raw,pins,1000)
        self.assertEqual((result["sequence"],result["signatures"]),(2,2))
        self.assertFalse(result["full_time_ladder_verified"])

    def test_every_truncated_prefix_and_trailing_byte_is_refused(self):
        raw,pins=fixture()
        for truncated in [raw[:n] for n in range(len(raw))] + [raw+b"\0"]:
            with self.assertRaises(oracle.Refused):oracle.verify(truncated,pins,1000)

    def test_signature_body_and_checkpoint_mutations_fail(self):
        raw,pins=fixture()
        for offset in (8,10,15,28,60,92,100,116,120,200,len(raw)-1):
            changed=bytearray(raw);changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(oracle.Refused):oracle.verify(bytes(changed),pins,1000)

    def test_scope_time_and_sequence_boundaries(self):
        raw,pins=fixture()
        for now in (999,1050,True):
            with self.assertRaises(oracle.Refused):oracle.verify(raw,pins,now)
        self.assertEqual(oracle.verify(raw,pins,1049)["status"],"passed")
        for field,value in (("policy_digest","03"*32),("route_scope_digest","04"*32),("minimum_sequence",3)):
            with self.assertRaises(oracle.Refused):oracle.verify(raw,dict(pins,**{field:value}),1000)

    def test_duplicate_signers_unknown_authority_and_threshold(self):
        raw,pins=fixture()
        for field,value in (("threshold",3),("threshold",True),("public_keys",pins["public_keys"][:1]*2)):
            with self.assertRaises(oracle.Refused):oracle.verify(raw,dict(pins,**{field:value}),1000)
        for index in (0,99):
            changed=bytearray(raw);changed[-66:-64]=struct.pack(">H",index)
            with self.assertRaises(oracle.Refused):oracle.verify(bytes(changed),pins,1000)

    def test_duplicate_json_keys_and_noncanonical_hex(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"pins.json";path.write_text('{"threshold":1,"threshold":2}')
            with self.assertRaises(oracle.Refused):oracle.load_json(path)
        for value in ("AA"*32,"0 "*32,"00"*31):
            with self.assertRaises(oracle.Refused):oracle.hex_bytes(value,32)


class TimeRefreshPublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name);self.root.chmod(0o700)
        self.raw,self.pins=fixture()

    def test_publish_idempotence_and_signed_successor(self):
        self.assertEqual(publisher.publish(self.raw,self.pins,self.root,1000)["status"],"published")
        self.assertEqual((self.root/publisher.TARGET).read_bytes(),self.raw)
        self.assertEqual((self.root/publisher.TARGET).stat().st_mode&0o777,0o600)
        self.assertEqual(publisher.publish(self.raw,self.pins,self.root,1000)["status"],"already_published")
        newer,pins=fixture(3,1001)
        self.assertEqual(publisher.publish(newer,pins,self.root,1001)["sequence"],3)

    def test_rollback_and_equivocation_preserve_previous_file(self):
        publisher.publish(self.raw,self.pins,self.root,1000)
        for raw,pins in (fixture(1,1000),fixture(2,1001)):
            with self.assertRaises(oracle.Refused):publisher.publish(raw,pins,self.root,1001)
            self.assertEqual((self.root/publisher.TARGET).read_bytes(),self.raw)

    def test_invalid_signature_or_expiry_does_not_create_evidence(self):
        changed=bytearray(self.raw);changed[-1]^=1
        for raw,now in ((bytes(changed),1000),(self.raw,1050)):
            with self.assertRaises(oracle.Refused):publisher.publish(raw,self.pins,self.root,now)
            self.assertFalse((self.root/publisher.TARGET).exists())

    def test_symlink_hardlink_and_public_directory_are_refused(self):
        other=self.root/"other";other.write_bytes(self.raw);other.chmod(0o600)
        target=self.root/publisher.TARGET;target.symlink_to(other)
        with self.assertRaises((OSError,oracle.Refused)):publisher.publish(self.raw,self.pins,self.root,1000)
        target.unlink();os.link(other,target)
        with self.assertRaises(oracle.Refused):publisher.publish(self.raw,self.pins,self.root,1000)
        target.unlink();self.root.chmod(0o755)
        with self.assertRaises(oracle.Refused):publisher.publish(self.raw,self.pins,self.root,1000)

    def test_failure_before_rename_keeps_previous_and_cleans_staging(self):
        publisher.publish(self.raw,self.pins,self.root,1000)
        newer,pins=fixture(3,1001)
        with mock.patch.object(publisher.os,"replace",side_effect=OSError("injected rename failure")):
            with self.assertRaises(OSError):publisher.publish(newer,pins,self.root,1001)
        self.assertEqual((self.root/publisher.TARGET).read_bytes(),self.raw)
        self.assertEqual(list(self.root.glob("*.new")),[])

    def test_failed_directory_sync_is_completed_by_idempotent_retry(self):
        real_sync=os.fsync
        calls=[]
        def fail_second(fd):
            calls.append(fd)
            if len(calls)==2:raise OSError("injected directory sync failure")
            real_sync(fd)
        with mock.patch.object(publisher.os,"fsync",side_effect=fail_second):
            with self.assertRaises(OSError):publisher.publish(self.raw,self.pins,self.root,1000)
        self.assertEqual((self.root/publisher.TARGET).read_bytes(),self.raw)
        with mock.patch.object(publisher.os,"fsync",wraps=real_sync) as sync:
            self.assertEqual(publisher.publish(self.raw,self.pins,self.root,1000)["status"],"already_published")
            self.assertGreaterEqual(sync.call_count,2)

    def test_fifo_is_refused_without_waiting_for_a_writer(self):
        os.mkfifo(self.root/publisher.TARGET,0o600)
        with self.assertRaises(oracle.Refused):publisher.publish(self.raw,self.pins,self.root,1000)


if __name__ == "__main__":unittest.main()
