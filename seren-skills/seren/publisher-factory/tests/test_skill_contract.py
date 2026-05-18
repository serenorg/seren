from pathlib import Path
import re
import unittest


SKILL_PATH = Path(__file__).resolve().parents[1] / "SKILL.md"


class PublisherFactorySkillContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = SKILL_PATH.read_text(encoding="utf-8")
        cls.lower_content = cls.content.lower()

    def test_skill_identity_and_live_catalog_guard(self):
        self.assertIn("name: publisher-factory", self.content)
        self.assertIn("list_agent_publishers", self.content)
        self.assertRegex(
            self.lower_content,
            r"no arguments|without arguments|empty argument",
        )
        self.assertIn("third-party", self.lower_content)

    def test_research_scope_and_verification_gates(self):
        self.assertIn("top 10 competitors", self.lower_content)
        self.assertIn("20 companies total", self.lower_content)
        self.assertIn("perplexity", self.lower_content)
        self.assertIn("public api docs", self.lower_content)
        self.assertIn("skip", self.lower_content)

    def test_publisher_contract_matches_required_shape(self):
        required_phrases = [
            "integration_type: api",
            "publisher_category: integration",
            "x402_per_request",
            "undocumented_endpoint_policy: default_deny",
            "clone the live asana",
            "oauth",
            "api key",
            "protected",
            "logo_status: missing",
            "do not persist",
        ]

        for phrase in required_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.lower_content)

    def test_report_groups_are_declared(self):
        for group in ["deployed", "existing", "updated", "skipped", "blocked"]:
            with self.subTest(group=group):
                self.assertTrue(
                    re.search(rf"`?{group}`?", self.content),
                    f"missing report group: {group}",
                )


if __name__ == "__main__":
    unittest.main()
