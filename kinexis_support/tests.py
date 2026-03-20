from unittest import TestCase

from kinexis_support.services.secrets_refresh.domain import (
    RefreshSecretsError,
    SecretsHeader,
    apply_substitutions,
    canonical_env_text,
    compute_digest,
    parse_env_body,
    parse_header,
    render_env_body,
    render_header,
    render_updated_file,
)
from kinexis_support.services.secrets_refresh.op_client import (
    OpClient,
    fetch_env_from_items,
    fields_to_env,
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


# ---------------------------------------------------------------------------
# fields_to_env
# ---------------------------------------------------------------------------

class TestFieldsToEnv(TestCase):

    def _item(self, fields):
        return {"fields": fields}

    def test_notes_field_parsed_as_key_value(self):
        item = self._item([{
            "id": "notesPlain",
            "value": "KEY=value\nOTHER=123\n",
        }])
        env = fields_to_env(item)
        self.assertEqual(env["KEY"], "value")
        self.assertEqual(env["OTHER"], "123")

    def test_notes_blank_lines_and_comments_skipped(self):
        item = self._item([{
            "id": "notesPlain",
            "value": "\n# comment\nKEY=value\n",
        }])
        env = fields_to_env(item)
        self.assertEqual(list(env.keys()), ["KEY"])

    def test_notes_lines_without_equals_skipped(self):
        item = self._item([{
            "id": "notesPlain",
            "value": "INVALID\nKEY=value\n",
        }])
        env = fields_to_env(item)
        self.assertNotIn("INVALID", env)

    def test_notes_invalid_key_raises(self):
        item = self._item([{
            "id": "notesPlain",
            "value": "123INVALID=value\n",
        }])
        with self.assertRaises(RefreshSecretsError):
            fields_to_env(item)

    def test_custom_field_label_used_as_key(self):
        item = self._item([{"label": "MY_VAR", "value": "hello"}])
        env = fields_to_env(item)
        self.assertEqual(env["MY_VAR"], "hello")

    def test_skips_username_purpose(self):
        item = self._item([{"label": "username", "value": "user", "purpose": "USERNAME"}])
        env = fields_to_env(item)
        self.assertNotIn("username", env)

    def test_skips_password_purpose(self):
        item = self._item([{"label": "password", "value": "secret", "purpose": "PASSWORD"}])
        env = fields_to_env(item)
        self.assertNotIn("password", env)

    def test_skips_structured_values(self):
        item = self._item([{"label": "MY_VAR", "value": {"nested": "dict"}}])
        env = fields_to_env(item)
        self.assertNotIn("MY_VAR", env)

    def test_invalid_field_label_raises(self):
        item = self._item([{"label": "123INVALID", "value": "val"}])
        with self.assertRaises(RefreshSecretsError):
            fields_to_env(item)

    def test_skips_field_without_label(self):
        item = self._item([{"value": "val"}])
        env = fields_to_env(item)
        self.assertEqual(env, {})

    def test_value_with_equals_sign(self):
        item = self._item([{
            "id": "notesPlain",
            "value": "URL=postgres://user:pass@host/db?ssl=true\n",
        }])
        env = fields_to_env(item)
        self.assertEqual(env["URL"], "postgres://user:pass@host/db?ssl=true")

    def test_empty_item(self):
        self.assertEqual(fields_to_env({}), {})
        self.assertEqual(fields_to_env({"fields": []}), {})


# ---------------------------------------------------------------------------
# fetch_env_from_items
# ---------------------------------------------------------------------------

class MockRunner:
    def __init__(self, responses):
        self._responses = responses  # dict: item_name -> json string

    def run(self, cmd):
        item = cmd[3]  # op item get <item> ...
        import json
        return json.dumps(self._responses[item])


class TestFetchEnvFromItems(TestCase):

    def _make_item(self, notes):
        return {"fields": [{"id": "notesPlain", "value": notes}]}

    def test_merges_multiple_items(self):
        runner = MockRunner({
            "item1": self._make_item("A=1\n"),
            "item2": self._make_item("B=2\n"),
        })
        op = OpClient(runner=runner)
        env = fetch_env_from_items(op, "vault", ["item1", "item2"])
        self.assertEqual(env["A"], "1")
        self.assertEqual(env["B"], "2")

    def test_later_item_overrides_earlier(self):
        runner = MockRunner({
            "item1": self._make_item("KEY=first\n"),
            "item2": self._make_item("KEY=second\n"),
        })
        op = OpClient(runner=runner)
        env = fetch_env_from_items(op, "vault", ["item1", "item2"])
        self.assertEqual(env["KEY"], "second")


# ---------------------------------------------------------------------------
# OpClient
# ---------------------------------------------------------------------------

class TestOpClient(TestCase):

    def test_parses_valid_json(self):
        import json

        class FixedRunner:
            def run(self, cmd):
                return json.dumps({"fields": []})

        op = OpClient(runner=FixedRunner())
        result = op.item_get_json("vault", "item")
        self.assertEqual(result, {"fields": []})

    def test_invalid_json_raises(self):
        class BadRunner:
            def run(self, cmd):
                return "not json"

        op = OpClient(runner=BadRunner())
        with self.assertRaises(RefreshSecretsError):
            op.item_get_json("vault", "item")
