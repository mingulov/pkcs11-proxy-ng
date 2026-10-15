"""Secure readiness recipes (RO-05).

A config whose remote listener is mTLS must not advertise a
plaintext readiness recipe: the documented probe uses HTTPS, the
full client TLS material, and a certificate-name override for
loopback. Plaintext recipes stay a negative control, never the
recommendation.
"""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Sample configs covered by the recipe rule (repo-relative paths).
RECIPE_CHECKED_CONFIGS = (
    "examples/configs/prod/proxy.toml",
    "examples/configs/staging/proxy.toml",
    "examples/configs/bundle/proxy.toml",
    "examples/configs/fips/proxy.toml",
    "packaging/windows/proxy.toml.template",
)

REQUIRED_TLS_FLAGS = (
    "--tls-ca-cert",
    "--tls-client-cert",
    "--tls-client-key",
    "--tls-domain",
)


def extract_exec_recipes(text):
    """``exec: [...]`` argv arrays quoted inside TOML comments."""
    recipes = []
    in_exec = False
    depth = 0
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        body = stripped[1:]
        if not in_exec:
            if "exec:" in body and "[" in body:
                in_exec = True
                current = body.split("[", 1)[1]
                depth = 1
            continue
        current += " " + body
        for char in body:
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
        if depth <= 0:
            in_exec = False
            recipes.append(re.findall(r'"([^"]*)"', current))
    return recipes


class ReadinessRecipeTests(unittest.TestCase):
    def test_mtls_listeners_pair_with_https_recipes_only(self):
        checked = 0
        for relative in RECIPE_CHECKED_CONFIGS:
            path = ROOT / relative
            text = path.read_text(encoding="utf-8")
            config = tomllib.loads(text)
            auth = (config.get("listener", {}).get("remote", {}).get("auth"))
            for argv in extract_exec_recipes(text):
                if "health" not in argv:
                    continue
                checked += 1
                with self.subTest(config=relative, argv=argv):
                    self.assertEqual(auth, "mtls",
                                     "readiness recipes are only checked on mTLS listeners")
                    endpoints = [arg for arg in argv
                                 if arg.startswith("http://") or arg.startswith("https://")]
                    self.assertEqual(len(endpoints), 1,
                                     f"recipe must probe exactly one endpoint: {argv}")
                    self.assertTrue(endpoints[0].startswith("https://"),
                                    f"mTLS readiness must use https, got: {endpoints[0]}")
                    for flag in REQUIRED_TLS_FLAGS:
                        self.assertIn(flag, argv,
                                      f"mTLS readiness lacks {flag}: {argv}")
        self.assertGreater(checked, 0, "must check at least one readiness recipe")

    def test_prod_recipe_names_loopback_sni_override(self):
        text = (ROOT / "examples/configs/prod/proxy.toml").read_text(encoding="utf-8")
        recipes = [argv for argv in extract_exec_recipes(text) if "health" in argv]
        self.assertEqual(len(recipes), 1, "prod must carry exactly one health recipe")
        argv = recipes[0]
        endpoint = next(arg for arg in argv if "://" in arg)
        self.assertIn("127.0.0.1", endpoint, "pod-local probe must target loopback")
        self.assertIn("--tls-domain", argv, "loopback probe needs an SNI override flag")
        domain = argv[argv.index("--tls-domain") + 1]
        self.assertNotIn("127.0.0.1", domain,
                         "loopback probes need a certificate-name override, not the IP")

    def test_no_plaintext_health_endpoint_advertised_on_mtls(self):
        for relative in RECIPE_CHECKED_CONFIGS:
            path = ROOT / relative
            config = tomllib.loads(path.read_text(encoding="utf-8"))
            if config.get("listener", {}).get("remote", {}).get("auth") != "mtls":
                continue
            for argv in extract_exec_recipes(path.read_text(encoding="utf-8")):
                if "health" not in argv:
                    continue
                with self.subTest(config=relative):
                    self.assertFalse(any(arg.startswith("http://") for arg in argv),
                                     f"plaintext health recipe on mTLS listener: {argv}")


if __name__ == "__main__":
    unittest.main()
