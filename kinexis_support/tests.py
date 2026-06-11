from unittest import TestCase

from kinexis_support.services.secrets_refresh.domain import (
    RefreshSecretsError,
    SecretsHeader,
    apply_substitutions,
    canonical_env_text,
    compute_digest,
    parse_dotenv,
    parse_env_body,
    parse_header,
    render_env_body,
    render_header,
    render_updated_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HEADER_LINES = [
    "# @secrets:\n",
    "#   vault: RUTA IT\n",
    "#   items: app:dev, db:sqlite\n",
    "#   digest_alg: hmac-sha256\n",
    "#   digest: abc123\n",
    "#   updated_at: 2024-01-01T00:00:00Z\n",
    "# @endsecrets\n",
]


def make_file_lines(header=None, body=None):
    lines = list(header or VALID_HEADER_LINES)
    lines.append("\n")
    lines.extend(body or [])
    return lines


# ---------------------------------------------------------------------------
# parse_header
# ---------------------------------------------------------------------------

class TestParseHeader(TestCase):

    def test_parses_valid_header(self):
        header, start, end = parse_header(VALID_HEADER_LINES)
        self.assertEqual(header.vault, "RUTA IT")
        self.assertEqual(header.items, ["app:dev", "db:sqlite"])
        self.assertEqual(header.digest_alg, "hmac-sha256")
        self.assertEqual(header.digest_hex, "abc123")
        self.assertEqual(header.updated_at, "2024-01-01T00:00:00Z")
        self.assertEqual(start, 0)
        self.assertEqual(end, 6)

    def test_missing_header_raises(self):
        with self.assertRaises(RefreshSecretsError):
            parse_header(["KEY=value\n"])

    def test_missing_vault_raises(self):
        lines = [
            "# @secrets:\n",
            "#   items: app:dev\n",
            "# @endsecrets\n",
        ]
        with self.assertRaises(RefreshSecretsError):
            parse_header(lines)

    def test_missing_items_raises(self):
        lines = [
            "# @secrets:\n",
            "#   vault: RUTA IT\n",
            "# @endsecrets\n",
        ]
        with self.assertRaises(RefreshSecretsError):
            parse_header(lines)

    def test_empty_items_raises(self):
        lines = [
            "# @secrets:\n",
            "#   vault: RUTA IT\n",
            "#   items: \n",
            "# @endsecrets\n",
        ]
        with self.assertRaises(RefreshSecretsError):
            parse_header(lines)

    def test_optional_fields_default(self):
        lines = [
            "# @secrets:\n",
            "#   vault: RUTA IT\n",
            "#   items: app:dev\n",
            "# @endsecrets\n",
        ]
        header, _, _ = parse_header(lines)
        self.assertEqual(header.digest_alg, "hmac-sha256")
        self.assertIsNone(header.digest_hex)
        self.assertIsNone(header.updated_at)

    def test_multiple_items_parsed(self):
        lines = [
            "# @secrets:\n",
            "#   vault: RUTA IT\n",
            "#   items: app:dev, db:sqlite, svc:ai\n",
            "# @endsecrets\n",
        ]
        header, _, _ = parse_header(lines)
        self.assertEqual(header.items, ["app:dev", "db:sqlite", "svc:ai"])

    def test_header_not_at_start(self):
        lines = ["# some comment\n"] + VALID_HEADER_LINES
        header, start, end = parse_header(lines)
        self.assertEqual(start, 1)
        self.assertEqual(header.vault, "RUTA IT")


# ---------------------------------------------------------------------------
# parse_env_body
# ---------------------------------------------------------------------------

class TestParseEnvBody(TestCase):

    def test_parses_key_value_pairs(self):
        lines = make_file_lines(body=["KEY=value\n", "OTHER=123\n"])
        _, _, end = parse_header(lines)
        env = parse_env_body(lines, end)
        self.assertEqual(env["KEY"], "value")
        self.assertEqual(env["OTHER"], "123")

    def test_skips_blank_lines_and_comments(self):
        lines = make_file_lines(body=["\n", "# comment\n", "KEY=value\n"])
        _, _, end = parse_header(lines)
        env = parse_env_body(lines, end)
        self.assertEqual(list(env.keys()), ["KEY"])

    def test_value_with_equals_sign(self):
        lines = make_file_lines(body=["URL=postgres://user:pass@host/db?ssl=true\n"])
        _, _, end = parse_header(lines)
        env = parse_env_body(lines, end)
        self.assertEqual(env["URL"], "postgres://user:pass@host/db?ssl=true")

    def test_empty_body(self):
        lines = make_file_lines()
        _, _, end = parse_header(lines)
        env = parse_env_body(lines, end)
        self.assertEqual(env, {})

    def test_skips_lines_without_equals(self):
        lines = make_file_lines(body=["INVALID\n", "KEY=value\n"])
        _, _, end = parse_header(lines)
        env = parse_env_body(lines, end)
        self.assertNotIn("INVALID", env)
        self.assertIn("KEY", env)


# ---------------------------------------------------------------------------
# parse_dotenv (plain KEY=value files, e.g. op inject output)
# ---------------------------------------------------------------------------

class TestParseDotenv(TestCase):

    def test_plain_key_values_no_header(self):
        env = parse_dotenv(["A=1\n", "B=2\n"])
        self.assertEqual(env, {"A": "1", "B": "2"})

    def test_skips_blank_lines_and_comments(self):
        env = parse_dotenv(["\n", "# comment\n", "A=1\n"])
        self.assertEqual(list(env.keys()), ["A"])

    def test_skips_lines_without_equals(self):
        env = parse_dotenv(["INVALID\n", "KEY=value\n"])
        self.assertNotIn("INVALID", env)
        self.assertEqual(env["KEY"], "value")

    def test_value_with_equals_sign(self):
        env = parse_dotenv(["URL=postgres://user:pass@host/db?ssl=true\n"])
        self.assertEqual(env["URL"], "postgres://user:pass@host/db?ssl=true")

    def test_empty_input(self):
        self.assertEqual(parse_dotenv([]), {})


# ---------------------------------------------------------------------------
# canonical_env_text
# ---------------------------------------------------------------------------

class TestCanonicalEnvText(TestCase):

    def test_sorted_output(self):
        env = {"Z": "last", "A": "first", "M": "mid"}
        text = canonical_env_text(env)
        self.assertEqual(text, "A=first\nM=mid\nZ=last\n")

    def test_trailing_newline(self):
        text = canonical_env_text({"KEY": "val"})
        self.assertTrue(text.endswith("\n"))

    def test_empty_env(self):
        self.assertEqual(canonical_env_text({}), "\n")


# ---------------------------------------------------------------------------
# compute_digest
# ---------------------------------------------------------------------------

class TestComputeDigest(TestCase):

    def test_sha256(self):
        env = {"KEY": "value"}
        digest = compute_digest(env, "sha256", None)
        self.assertEqual(len(digest), 64)

    def test_hmac_sha256(self):
        env = {"KEY": "value"}
        digest = compute_digest(env, "hmac-sha256", b"secret")
        self.assertEqual(len(digest), 64)

    def test_hmac_sha256_missing_key_raises(self):
        with self.assertRaises(RefreshSecretsError):
            compute_digest({"KEY": "value"}, "hmac-sha256", None)

    def test_unsupported_alg_raises(self):
        with self.assertRaises(RefreshSecretsError):
            compute_digest({"KEY": "value"}, "md5", None)

    def test_deterministic(self):
        env = {"KEY": "value"}
        self.assertEqual(
            compute_digest(env, "hmac-sha256", b"key"),
            compute_digest(env, "hmac-sha256", b"key"),
        )

    def test_different_keys_produce_different_digests(self):
        env = {"KEY": "value"}
        self.assertNotEqual(
            compute_digest(env, "hmac-sha256", b"key1"),
            compute_digest(env, "hmac-sha256", b"key2"),
        )


# ---------------------------------------------------------------------------
# render_header / render_env_body / render_updated_file
# ---------------------------------------------------------------------------

class TestRenderHeader(TestCase):

    def test_output_format(self):
        header = SecretsHeader(vault="RUTA IT", items=["app:dev", "svc:ai"])
        lines = render_header(header, "deadbeef", "2024-01-01T00:00:00Z")
        joined = "".join(lines)
        self.assertIn("# @secrets:", joined)
        self.assertIn("vault: RUTA IT", joined)
        self.assertIn("items: app:dev, svc:ai", joined)
        self.assertIn("digest: deadbeef", joined)
        self.assertIn("updated_at: 2024-01-01T00:00:00Z", joined)
        self.assertIn("# @endsecrets", joined)


class TestRenderEnvBody(TestCase):

    def test_sorted_output(self):
        lines = render_env_body({"Z": "last", "A": "first"})
        self.assertEqual(lines[0], "A=first\n")
        self.assertEqual(lines[1], "Z=last\n")

    def test_each_line_ends_with_newline(self):
        for line in render_env_body({"K": "v"}):
            self.assertTrue(line.endswith("\n"))


class TestRenderUpdatedFile(TestCase):

    def test_header_before_body(self):
        header = SecretsHeader(vault="RUTA IT", items=["app:dev"])
        lines = render_updated_file(header, {"KEY": "val"}, "abc", "2024-01-01T00:00:00Z")
        joined = "".join(lines)
        self.assertLess(joined.index("@secrets"), joined.index("KEY=val"))


# ---------------------------------------------------------------------------
# apply_substitutions
# ---------------------------------------------------------------------------

class TestApplySubstitutions(TestCase):

    def test_now_replaced(self):
        env = {"GENERATED_AT": "{now}", "OTHER": "static"}
        result = apply_substitutions(env, "2024-01-01T00:00:00Z")
        self.assertEqual(result["GENERATED_AT"], "2024-01-01T00:00:00Z")
        self.assertEqual(result["OTHER"], "static")

    def test_no_placeholder_unchanged(self):
        env = {"KEY": "value"}
        result = apply_substitutions(env, "2024-01-01T00:00:00Z")
        self.assertEqual(result["KEY"], "value")

    def test_now_in_middle_of_value(self):
        env = {"KEY": "prefix_{now}_suffix"}
        result = apply_substitutions(env, "TS")
        self.assertEqual(result["KEY"], "prefix_TS_suffix")

    def test_original_env_not_mutated(self):
        env = {"KEY": "{now}"}
        apply_substitutions(env, "TS")
        self.assertEqual(env["KEY"], "{now}")

    def test_app_name_replaced(self):
        env = {"APP_NAME": "{app_name}"}
        result = apply_substitutions(env, "TS", app_name="openchannel")
        self.assertEqual(result["APP_NAME"], "openchannel")

    def test_app_env_replaced(self):
        env = {"APP_ENV": "{app_env}"}
        result = apply_substitutions(env, "TS", app_env="staging")
        self.assertEqual(result["APP_ENV"], "staging")

    def test_all_three_placeholders(self):
        env = {"META": "{app_name}:{app_env}@{now}"}
        result = apply_substitutions(env, "2024-01-01T00:00:00Z", app_name="myapp", app_env="prod")
        self.assertEqual(result["META"], "myapp:prod@2024-01-01T00:00:00Z")

    def test_app_name_empty_by_default(self):
        env = {"KEY": "{app_name}"}
        result = apply_substitutions(env, "TS")
        self.assertEqual(result["KEY"], "")

    def test_app_env_empty_by_default(self):
        env = {"KEY": "{app_env}"}
        result = apply_substitutions(env, "TS")
        self.assertEqual(result["KEY"], "")
