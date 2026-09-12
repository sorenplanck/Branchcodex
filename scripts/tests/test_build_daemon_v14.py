import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('build_daemon_v14',Path(__file__).resolve().parents[1]/'build_daemon_v14.py')
BUILD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)

class BuildPublicationTests(unittest.TestCase):
    def test_production_build_never_enables_evidence_or_simulation(self):
        command=BUILD.build_command('/usr/bin/cargo')
        self.assertIn('--locked',command)
        self.assertIn('--no-default-features',command)
        self.assertEqual(command[command.index('--features')+1],'production')

    def test_non_executable_keeps_previous_binary_untouched(self):
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';target=Path(root)/'daemon'
            source.write_bytes(b'cargo success text is not an executable')
            target.write_bytes(b'previous binary')
            with self.assertRaises(ValueError): BUILD.publish_elf(source,target)
            self.assertEqual(target.read_bytes(),b'previous binary')

    def test_symlink_artifact_is_refused_before_publication(self):
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';link=Path(root)/'link';target=Path(root)/'daemon'
            source.write_bytes(b'\x7fELF\x02'+b'\x00'*64)
            link.symlink_to(source)
            with self.assertRaises(ValueError): BUILD.publish_elf(link,target)
            self.assertFalse(target.exists())

    def test_exact_artifact_is_atomically_copied_and_hashed(self):
        # Synthetic ELF header tests the copy boundary, not executable validity.
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';target=Path(root)/'out/daemon'
            source.write_bytes(b'\x7fELF\x02'+b'\x00'*64)
            sha=BUILD.publish_elf(source,target)
            self.assertEqual(target.read_bytes(),source.read_bytes())
            self.assertEqual(sha,BUILD.digest(target))
            self.assertEqual(target.stat().st_mode & 0o777,0o755)
            self.assertEqual(list(target.parent.glob('.dom-interopd-*')),[])

if __name__=='__main__': unittest.main()
