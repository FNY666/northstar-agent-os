import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LANGUAGE_FILES = {
    "zh-CN": "docs/README.zh-CN.md",
    "zh-TW": "docs/README.zh-TW.md",
    "ja": "docs/README.ja.md",
    "es": "docs/README.es.md",
    "ko": "docs/README.ko.md",
    "fr": "docs/README.fr.md",
    "de": "docs/README.de.md",
    "pt-BR": "docs/README.pt-BR.md",
    "it": "docs/README.it.md",
    "tr": "docs/README.tr.md",
    "vi": "docs/README.vi.md",
}

REQUIRED_MARKERS = (
    "Northstar Codex Sidecar",
    "OpenBot",
    "Unix",
    "read-only",
    "ephemeral",
)

LANGUAGE_MARKERS = {
    "zh-CN": ("简体中文", "一句话说明"),
    "zh-TW": ("繁體中文", "一句話說明"),
    "ja": ("日本語", "これは"),
}


class DocumentationStructureTests(unittest.TestCase):
    def test_root_readme_exposes_all_supported_language_entries(self):
        text = README.read_text(encoding="utf-8")
        for language, relative_path in LANGUAGE_FILES.items():
            self.assertIn(relative_path, text, f"missing language link: {language}")
        self.assertIn("English is the canonical", text)

    def test_each_language_entry_has_scope_and_security_boundary(self):
        for language, relative_path in LANGUAGE_FILES.items():
            path = ROOT / relative_path
            self.assertTrue(path.is_file(), f"missing file: {relative_path}")
            text = path.read_text(encoding="utf-8")
            self.assertGreater(len(text), 1200, f"entry is too short: {language}")
            for marker in REQUIRED_MARKERS:
                self.assertIn(marker, text, f"{language} missing marker {marker}")
            for marker in LANGUAGE_MARKERS.get(language, ()):
                self.assertIn(marker, text, f"{language} is not translated: {marker}")
            self.assertRegex(text, r"(?i)(not|not yet|未|不|まだ|no es|nicht|não|non).{0,100}(complete|finished|完整|完成|完全|completo|completa|vollständig|complet|완성)", f"{language} lacks incomplete-platform disclaimer")
            self.assertRegex(text, r"(?i)(canonical|规范|正本|原文|原本|基準|canónico|canonique|kanonisch|canônica|canonico|kanonik|chuẩn)", f"{language} lacks translation maintenance note")

    def test_language_links_are_repository_relative(self):
        text = README.read_text(encoding="utf-8")
        links = re.findall(r"\]\((docs/README\.[^)]+\.md)\)", text)
        self.assertEqual(set(links), set(LANGUAGE_FILES.values()))


if __name__ == "__main__":
    unittest.main()
