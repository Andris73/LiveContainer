import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PackageWorkflowTests(unittest.TestCase):
    def test_inherited_source_publisher_is_disabled_for_our_fork(self):
        text = (ROOT / '.github/workflows/update_source.yml').read_text()
        self.assertIn("if: github.repository == 'LiveContainerMirror/LiveContainer'", text)

    def test_packaging_requires_successful_native_run_and_cannot_publish(self):
        path = ROOT / '.github/workflows/package-watch.yml'
        self.assertTrue(path.is_file())
        text = path.read_text()
        for expected in ('workflow_dispatch:', 'native_run_id:', 'actions: read', 'contents: read', 'NATIVE_RUN_ID:', 'conclusion', 'success', 'head_sha', 'package-watch.sh'):
            self.assertIn(expected, text)
        self.assertNotRegex(text, r'contents:\s*write|gh release|publish-release|ALTSTORE_TOKEN')
        run_blocks = re.findall(r'^        run: \|\n((?:          [^\n]*\n)*)', text, re.MULTILINE)
        self.assertTrue(run_blocks)
        for block in run_blocks:
            self.assertNotIn('${{ inputs.native_run_id }}', block)


if __name__ == '__main__':
    unittest.main()
