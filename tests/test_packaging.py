"""Packaging metadata contract: pyproject must stay in sync with the code.

Stdlib-only (tomllib) so it runs in CI without installing the project.
"""

import fnmatch
import os
import pkgutil
import re
import tomllib
import unittest

import dast_harness
from dast_harness import cli

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")

PEP440 = re.compile(r"^\d+(\.\d+)*([abc]|rc)?\d*(\.post\d+)?(\.dev\d+)?$")


def _load():
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


class PyprojectTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(PYPROJECT), "pyproject.toml is missing")
        self.data = _load()

    def test_build_backend_is_declared(self):
        build = self.data["build-system"]
        self.assertIn("setuptools", build["build-backend"])
        self.assertTrue(build["requires"])

    def test_core_metadata(self):
        project = self.data["project"]
        self.assertEqual(project["name"], "dast-harness")
        self.assertEqual(project["requires-python"], ">=3.11")
        self.assertTrue(project["description"])
        self.assertEqual(project["readme"], "README.md")

    def test_no_runtime_dependencies(self):
        # CI installs nothing; the harness must stay stdlib-only.
        self.assertEqual(self.data["project"].get("dependencies", []), [])

    def test_version_has_a_single_source(self):
        project = self.data["project"]
        self.assertIn("version", project.get("dynamic", []))
        self.assertNotIn("version", project)
        attr = self.data["tool"]["setuptools"]["dynamic"]["version"]["attr"]
        self.assertEqual(attr, "dast_harness.__version__")
        self.assertRegex(dast_harness.__version__, PEP440)

    def test_console_script_points_at_the_cli(self):
        scripts = self.data["project"]["scripts"]
        self.assertEqual(scripts["dast-harness"], "dast_harness.cli:main")
        module, _, func = scripts["dast-harness"].partition(":")
        self.assertEqual(module, cli.__name__)
        self.assertTrue(callable(getattr(cli, func)))

    def test_every_subpackage_is_included(self):
        patterns = self.data["tool"]["setuptools"]["packages"]["find"]["include"]
        names = ["dast_harness"] + [
            f"dast_harness.{m.name}"
            for m in pkgutil.iter_modules(dast_harness.__path__)
            if m.ispkg
        ]
        for name in names:
            with self.subTest(package=name):
                self.assertTrue(
                    any(fnmatch.fnmatch(name, p) for p in patterns),
                    f"{name} is not covered by packages.find include={patterns}",
                )


if __name__ == "__main__":
    unittest.main()
