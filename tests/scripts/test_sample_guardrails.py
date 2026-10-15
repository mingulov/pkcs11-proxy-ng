"""Supported-sample guardrails (SEC-H1/H3).

Every recommended deployment sample carries the single-client
admission guardrail explicitly, while the reusable library default
stays untouched by this task.
"""

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Recommended samples: explicit `max_contexts = 1` required.
GUARDED_SAMPLES = (
    "examples/configs/prod/proxy.toml",
    "examples/configs/staging/proxy.toml",
    "examples/configs/fips/proxy.toml",
    "examples/configs/bundle/proxy.toml",
    "packaging/windows/proxy.toml.template",
)

# Reusable defaults: this task must not change them.
UNGUARDED_DEFAULTS = (
    "packaging/config/proxy.toml.default",
)


class SampleGuardrailTests(unittest.TestCase):
    def test_recommended_samples_cap_contexts_at_one(self):
        for relative in GUARDED_SAMPLES:
            with self.subTest(sample=relative):
                config = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
                self.assertEqual(config.get("proxy", {}).get("max_contexts"), 1,
                                 f"{relative} must set max_contexts = 1")

    def test_reusable_defaults_unchanged(self):
        for relative in UNGUARDED_DEFAULTS:
            with self.subTest(default=relative):
                config = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
                self.assertNotIn("max_contexts", config.get("proxy", {}),
                                 f"{relative} must keep deferring to the code default")

    def test_code_default_stays_1000(self):
        source = (ROOT / "crates/server/src/config.rs").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?s)fn default_max_contexts\(\) -> usize \{\s*1000\s*\}",
                         "default_max_contexts must stay 1000 in this task")


if __name__ == "__main__":
    unittest.main()
