#!/usr/bin/env python3
"""Small, read-only regressions for the source-template dependency exception."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_SPEC = importlib.util.spec_from_file_location(
    'xmr_v7_static_validate', ROOT / 'scripts/xmr-v7-static-validate.py',
)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError('validator module unavailable')
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)
TEMPLATE = ROOT / 'external-gpl/dom-xmr-sidecar/Cargo.toml'
LOCAL_DEPENDENCIES = ('xmr-key-image-proof', 'xmr-raw-tx-verify')


class InstallerTemplateScopeTests(unittest.TestCase):
    def admitted(self, dependency: str, **changes: object) -> bool:
        arguments = {
            'root': ROOT,
            'manifest': TEMPLATE,
            'package': 'dom-xmr-sidecar',
            'section': 'dependencies',
            'dependency': dependency,
            'spec': {'path': f'../{dependency}'},
        }
        arguments.update(changes)
        return VALIDATOR.installer_template_dependency(**arguments)

    def test_exact_template_and_installer_sources_are_admitted(self) -> None:
        for dependency in (*LOCAL_DEPENDENCIES, 'monero-wallet-ng'):
            with self.subTest(dependency=dependency):
                self.assertTrue(self.admitted(dependency))

    def test_installed_or_other_manifests_are_not_exempt(self) -> None:
        for manifest in (
            'sidecar-gpl/dom-xmr-sidecar/Cargo.toml',
            'sidecar-gpl/eigenwallet-xmr-sidecar/Cargo.toml',
            'external-gpl/other/Cargo.toml',
            'crates/adapters/xmr-raw-tx-verify/Cargo.toml',
        ):
            for dependency in (*LOCAL_DEPENDENCIES, 'monero-wallet-ng'):
                with self.subTest(manifest=manifest, dependency=dependency):
                    self.assertFalse(self.admitted(dependency, manifest=ROOT / manifest))

    def test_package_section_path_and_alias_are_exact(self) -> None:
        dependency = 'xmr-key-image-proof'
        for change in (
            {'package': 'other'},
            {'section': 'dev-dependencies'},
            {'section': 'build-dependencies'},
            {'spec': {'path': '../../xmr-key-image-proof'}},
            {'spec': {'path': '../elsewhere'}},
            {'spec': {'path': '../xmr-key-image-proof', 'package': 'other'}},
        ):
            with self.subTest(change=change):
                self.assertFalse(self.admitted(dependency, **change))
        self.assertFalse(self.admitted('unexpected-sibling'))

    def test_missing_local_origin_is_not_exempt(self) -> None:
        with patch.object(Path, 'is_file', return_value=False):
            for dependency in LOCAL_DEPENDENCIES:
                self.assertFalse(self.admitted(dependency))

    def test_bad_origin_identity_or_manifest_is_not_exempt(self) -> None:
        for contents in (
            '[package]\nname = "other"\n',
            'package = "not-a-table"\n',
            '[package\n',
        ):
            with self.subTest(contents=contents):
                with patch.object(Path, 'read_text', return_value=contents):
                    self.assertFalse(self.admitted('xmr-key-image-proof'))
        with patch.object(Path, 'read_text', side_effect=OSError('unavailable')):
            self.assertFalse(self.admitted('xmr-key-image-proof'))

    def test_template_or_origin_symlink_is_not_exempt(self) -> None:
        resolve = Path.resolve
        source = ROOT / 'crates/adapters/xmr-key-image-proof/Cargo.toml'
        for redirected in (TEMPLATE, source):
            def redirected_resolve(path: Path) -> Path:
                return ROOT / 'elsewhere/Cargo.toml' if path == redirected else resolve(path)

            with self.subTest(redirected=redirected):
                with patch.object(Path, 'resolve', autospec=True, side_effect=redirected_resolve):
                    self.assertFalse(self.admitted('xmr-key-image-proof'))

    def test_origins_are_the_exact_library_directories_copied_by_installer(self) -> None:
        tree = ast.parse((ROOT / 'scripts/install-sidecar-into-eigenwallet.py').read_text())
        copied_origins = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'shutil'
                and node.func.attr == 'copytree'
                and node.args
            ):
                source = node.args[0]
                if (
                    isinstance(source, ast.BinOp)
                    and isinstance(source.op, ast.Div)
                    and isinstance(source.left, ast.Name)
                    and source.left.id == 'HERE'
                    and isinstance(source.right, ast.Constant)
                ):
                    copied_origins.add(source.right.value)
        self.assertEqual(
            copied_origins,
            {f'crates/adapters/{name}' for name in LOCAL_DEPENDENCIES},
        )


if __name__ == '__main__':
    unittest.main()
