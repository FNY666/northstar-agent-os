"""The plugin bundle format: what a manifest may claim, and what it must not.

Three promises hold this module together, and every test below is one of them:

1. A bundle is a *packaging* format. Nothing in it can widen what the workspace already
   agreed to - ceilings are tighten-only, hooks are the veto-capable subset, and a path
   that leaves the bundle is refused rather than normalised.
2. The content digest is the unit of review. It is computed from disk, excludes the
   manifest's own ``[integrity]`` table (so a bundle cannot vouch for itself), and is the
   only thing a lockfile pins.
3. Export is honest. A capability a target cannot carry is *named* in ``Export.dropped``,
   computed from one table, never quietly omitted.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)

import command_hooks
import plugin_manifest as pm

MANIFEST_HEAD = (
    'schema_version = "northstar.plugin.v1"\n'
    'name = "demo"\n'
    'version = "0.1.0"\n'
    'publisher = "arena"\n'
    'description = "A bundle that does very little."\n'
)


class BundleTestCase(unittest.TestCase):
    """Temp-directory plumbing plus one place to write a manifest."""

    def setUp(self) -> None:
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-plugin-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)

    def bundle(self, manifest: str, files: dict[str, str] | None = None, *, name: str = "demo") -> Path:
        root = self.root / name
        root.mkdir(parents=True, exist_ok=True)
        (root / pm.MANIFEST_NAME).write_text(manifest, encoding="utf-8")
        for relative, text in (files or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def parse(self, root: Path, **kwargs) -> pm.PluginManifest:
        return pm.parse_manifest(pm.load_bundle(root), **kwargs)


class FormatTests(BundleTestCase):
    def test_a_minimal_bundle_parses(self):
        manifest = self.parse(self.bundle(MANIFEST_HEAD))
        self.assertEqual(manifest.name, "demo")
        self.assertEqual(manifest.version, "0.1.0")
        self.assertEqual(manifest.platforms, ("any",))
        self.assertEqual(pm.declared_components(manifest), set())

    def test_required_fields_are_required(self):
        for missing in ("name", "version", "publisher", "description", "schema_version"):
            with self.subTest(missing=missing):
                text = "\n".join(
                    line for line in MANIFEST_HEAD.splitlines() if not line.startswith(f"{missing} =")
                )
                with self.assertRaises(pm.PluginError) as caught:
                    self.parse(self.bundle(text + "\n"))
                self.assertIn(missing, str(caught.exception))

    def test_an_unknown_key_is_refused_rather_than_ignored(self):
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(self.bundle(MANIFEST_HEAD + 'on_ready = "curl | sh"\n'))
        message = str(caught.exception)
        self.assertIn("on_ready", message)
        self.assertIn("A key nobody reads", message, "the refusal has to say why it is a refusal")

    def test_names_are_lowercase_and_path_safe(self):
        for name in ("Demo", "with space", "../escape", "x" * 65, ""):
            with self.subTest(name=name):
                text = "\n".join(
                    line for line in MANIFEST_HEAD.splitlines() if not line.startswith("name =")
                )
                with self.assertRaises(pm.PluginError):
                    self.parse(self.bundle(text + f'\nname = "{name}"\n'))

    def test_version_is_a_label_not_a_range(self):
        text = MANIFEST_HEAD.replace('version = "0.1.0"', 'version = ">=0.1"')
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(self.bundle(text))
        self.assertIn("MAJOR.MINOR.PATCH", str(caught.exception))


class BundleFileTests(BundleTestCase):
    def test_declared_paths_must_exist_inside_the_bundle(self):
        root = self.bundle(MANIFEST_HEAD + "\n[components]\nskills = [\"skills\"]\n")
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(root)
        self.assertIn("skills", str(caught.exception))

    def test_a_path_that_escapes_the_bundle_is_refused(self):
        (self.root / "outside").mkdir(exist_ok=True)
        root = self.bundle(MANIFEST_HEAD + '\n[components]\nskills = ["../outside"]\n')
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(root)
        self.assertIn("outside the plugin directory", str(caught.exception))

    def test_symlinks_are_not_followed_into_the_bundle(self):
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "SKILL.md").write_text("---\nname: v\ndescription: d\n---\n\n", encoding="utf-8")
        root = self.bundle(MANIFEST_HEAD + '\n[components]\nskills = ["skills"]\n')
        (root / "skills").symlink_to(victim)
        with self.assertRaises(pm.PluginError):
            pm.load_bundle(root)

    def test_file_and_size_caps_are_enforced(self):
        root = self.bundle(MANIFEST_HEAD, {f"f{i}.txt": "x" for i in range(pm.MAX_FILES + 1)})
        with self.assertRaises(pm.PluginError) as caught:
            pm.load_bundle(root)
        self.assertIn("files", str(caught.exception).lower())
        big = self.bundle(MANIFEST_HEAD, {"big.txt": "x" * (pm.MAX_FILE_BYTES + 1)})
        with self.assertRaises(pm.PluginError):
            pm.load_bundle(big)

    def test_the_manifest_itself_is_not_a_component_file(self):
        bundle = pm.load_bundle(self.bundle(MANIFEST_HEAD))
        self.assertNotIn(pm.MANIFEST_NAME, [item.relative_path for item in bundle.files])


class DigestTests(BundleTestCase):
    def test_the_digest_follows_the_files(self):
        root = self.bundle(MANIFEST_HEAD + '\n[components]\nskills = ["skills"]\n', {"skills/a/SKILL.md": "one\n"})
        first = pm.load_bundle(root).content_digest
        (root / "skills" / "a" / "SKILL.md").write_text("two\n", encoding="utf-8")
        second = pm.load_bundle(root).content_digest
        self.assertTrue(first.startswith("sha256:"))
        self.assertNotEqual(first, second)

    def test_the_digest_ignores_the_integrity_table_so_a_bundle_cannot_vouch_for_itself(self):
        plain = self.bundle(MANIFEST_HEAD)
        sealed = self.bundle(MANIFEST_HEAD + '\n[integrity]\nseal = "deadbeef"\nseal_key_env = "NS_KEY"\n')
        self.assertEqual(pm.load_bundle(plain).content_digest, pm.load_bundle(sealed).content_digest)

    def test_the_manifest_may_not_pin_its_own_hash(self):
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(self.bundle(MANIFEST_HEAD + '\n[integrity]\nsha256 = "abc"\n'))
        self.assertIn("sha256", str(caught.exception))

    def test_concatenation_cannot_produce_a_colliding_digest(self):
        # The framing is length-prefixed exactly so: two bundles whose files split the same
        # bytes differently must not hash the same.
        a = self.bundle(MANIFEST_HEAD + '\n[components]\nskills = ["skills"]\n', {"skills/a/SKILL.md": "ab", "skills/b/SKILL.md": "c"}, name="a")
        b = self.bundle(MANIFEST_HEAD + '\n[components]\nskills = ["skills"]\n', {"skills/a/SKILL.md": "a", "skills/b/SKILL.md": "bc"}, name="b")
        self.assertNotEqual(pm.load_bundle(a).content_digest, pm.load_bundle(b).content_digest)


class HookClaimTests(BundleTestCase):
    HEAD = MANIFEST_HEAD + "\n[components]\n"

    def hook(self, body: str) -> Path:
        return self.bundle(self.HEAD + body)

    def test_a_hook_claim_becomes_a_table_the_real_validator_accepts(self):
        root = self.hook(
            '[[components.hooks]]\nevent = "PreToolUse"\ntool = "Write"\nscript = "guard.py"\ninterpreter = "python3"\ntimeout_ms = 1500\n'
        )
        (root / "guard.py").write_text("pass\n", encoding="utf-8")
        manifest = self.parse(root)
        table = manifest.hooks[0].as_hook_table()
        self.assertEqual(set(table), {"event", "script", "timeout_ms", "interpreter", "tool"})
        hooks = command_hooks.parse_hooks([table], workspace=root, known_tools=["Write"])
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0].timeout_ms, 1500)
        # Not "empty command": the field does not exist, which is the difference between a
        # hook that cannot be given a shell line and one that is merely not using it now.
        self.assertFalse(hasattr(hooks[0], "command"))

    def test_only_veto_capable_events_may_be_declared(self):
        for event in ("PostToolUse", "Stop", "SessionEnd"):
            with self.subTest(event=event):
                root = self.hook(f'[[components.hooks]]\nevent = "{event}"\nscript = "g.py"\n')
                (root / "g.py").write_text("pass\n", encoding="utf-8")
                with self.assertRaises(pm.PluginError) as caught:
                    self.parse(root)
                self.assertIn("veto-capable", str(caught.exception))

    def test_interpreters_are_an_allowlist(self):
        root = self.hook('[[components.hooks]]\nevent = "PreToolUse"\nscript = "g.py"\ninterpreter = "/bin/sh"\n')
        (root / "g.py").write_text("pass\n", encoding="utf-8")
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(root)
        self.assertIn("interpreter", str(caught.exception))

    def test_timeouts_are_bounded_by_the_same_numbers_as_the_workspace_policy(self):
        self.assertEqual(pm.MIN_TIMEOUT_MS, command_hooks.MIN_TIMEOUT_MS)
        self.assertEqual(pm.MAX_TIMEOUT_MS, command_hooks.MAX_TIMEOUT_MS)
        for value in (f"timeout_ms = {pm.MIN_TIMEOUT_MS - 1}", f"timeout_ms = {pm.MAX_TIMEOUT_MS + 1}", 'timeout_ms = "fast"'):
            with self.subTest(value=value):
                root = self.hook(f'[[components.hooks]]\nevent = "PreToolUse"\nscript = "g.py"\n{value}\n')
                (root / "g.py").write_text("pass\n", encoding="utf-8")
                with self.assertRaises(pm.PluginError):
                    self.parse(root)

    def test_a_script_must_be_inside_the_bundle(self):
        with self.assertRaises(pm.PluginError):
            self.parse(self.hook('[[components.hooks]]\nevent = "PreToolUse"\nscript = "../escape.py"\n'))
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(self.hook('[[components.hooks]]\nevent = "PreToolUse"\nscript = "absent.py"\n'))
        self.assertIn("does not exist", str(caught.exception))

    def test_hook_count_cap_matches_the_workspace_rule(self):
        self.assertEqual(pm.MAX_HOOKS, command_hooks.MAX_HOOKS)
        body = "".join('[[components.hooks]]\nevent = "PreToolUse"\nscript = "g.py"\n' for _ in range(pm.MAX_HOOKS + 1))
        root = self.bundle(self.HEAD + body, {"g.py": "pass\n"})
        with self.assertRaises(pm.PluginError):
            self.parse(root)


class PolicyCeilingTests(BundleTestCase):
    def test_a_bundle_may_only_tighten(self):
        workspace = {"max_turns": 10, "deny_tools": ["Write"], "read_only": True}
        manifest = self.parse(
            self.bundle(MANIFEST_HEAD + '\n[policy]\nmax_turns = 5\ndeny_tools = ["Write", "Edit"]\n'),
            workspace_policy=workspace,
        )
        self.assertEqual(manifest.policy["max_turns"], 5)
        self.assertEqual(manifest.policy["deny_tools"], ["Write", "Edit"])
        looser = self.bundle(MANIFEST_HEAD + '\n[policy]\nmax_turns = 20\n')
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(looser, workspace_policy=workspace)
        self.assertIn("max_turns", str(caught.exception))
        # Dropping a denial the repository made is the escalation this check exists for.
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(
                self.bundle(MANIFEST_HEAD + '\n[policy]\ndeny_tools = ["Edit"]\n'), workspace_policy=workspace
            )
        self.assertIn("only add denials", str(caught.exception))

    def test_a_bundle_cannot_grant_itself_approvals(self):
        # `allow_tools` is not in the policy vocabulary at all: an artefact that arrives from
        # elsewhere cannot auto-approve anything, exactly as in .northstar/config.toml.
        with self.assertRaises(pm.PluginError) as caught:
            self.parse(self.bundle(MANIFEST_HEAD + '\n[policy]\nallow_tools = ["Write"]\n'), workspace_policy={})
        self.assertIn("allow_tools", str(caught.exception))

    def test_a_bundle_cannot_widen_a_mode_the_workspace_pinned(self):
        for mode in ('"bypassPermissions"', '"default"', '"plan"'):
            with self.subTest(mode=mode):
                error = None
                try:
                    self.parse(
                        self.bundle(MANIFEST_HEAD + f"\n[policy]\npermission_mode = {mode}\n"),
                        workspace_policy={"permission_mode": "plan"},
                    )
                except pm.PluginError as caught:
                    error = str(caught)
                if mode == '"plan"':
                    self.assertIsNone(error, "asking for the same ceiling the workspace has is not loosening")
                else:
                    self.assertIsNotNone(error, f"{mode} must not load")

    def test_approval_modes_are_not_values_a_bundle_can_ask_for_at_all(self):
        # Not "refused because the workspace did not ask for it" - refused because a bundle
        # naming them would be a bundle granting itself permission.
        for mode in ("bypassPermissions", "acceptEdits"):
            with self.subTest(mode=mode):
                with self.assertRaises(pm.PluginError) as caught:
                    self.parse(self.bundle(MANIFEST_HEAD + f'\n[policy]\npermission_mode = "{mode}"\n'), workspace_policy=None)
                self.assertIn("operator decision", str(caught.exception))

    def test_the_tighten_only_rule_is_the_same_rule_as_the_policy_files(self):
        # If policy_file ever changes its allowed keys, this is the test that says so.
        self.assertTrue(pm.ALLOWED_POLICY_KEYS <= policy_file_keys())


def policy_file_keys() -> frozenset[str]:
    import policy_file

    return policy_file._ALLOWED_KEYS


class IntegrityTests(BundleTestCase):
    KEY = "test-key"

    def sealed(self, *, wrong: bool = False) -> Path:
        root = self.bundle(MANIFEST_HEAD)
        digest = pm.load_bundle(root).content_digest
        manifest = pm.parse_manifest(pm.load_bundle(root))
        payload = f"northstar.plugin.v1\n{manifest.name}\n{manifest.version}\n{digest}".encode("utf-8")
        seal = hmac.new(self.KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        if wrong:
            seal = "0" * len(seal)
        path = root / pm.MANIFEST_NAME
        path.write_text(
            path.read_text(encoding="utf-8") + f'\n[integrity]\nseal = "{seal}"\nseal_key_env = "NS_PLUGIN_KEY"\n',
            encoding="utf-8",
        )
        return root

    def test_a_matching_seal_verifies(self):
        report = pm.verify_integrity(
            self.parse(self.sealed()), pinned_digest="", environment={"NS_PLUGIN_KEY": self.KEY}
        )
        self.assertEqual(report["seal"], "valid")
        self.assertTrue(report["ok"])

    def test_a_foreign_seal_fails_the_report_instead_of_passing_it(self):
        report = pm.verify_integrity(
            self.parse(self.sealed(wrong=True)), pinned_digest="", environment={"NS_PLUGIN_KEY": self.KEY}
        )
        self.assertEqual(report["seal"], "invalid")
        self.assertFalse(report["ok"])
        self.assertIn("did not come from the key holder", report["reason"])

    def test_a_declared_seal_with_no_key_refuses_rather_than_shrugging(self):
        with self.assertRaises(pm.PluginError) as caught:
            pm.verify_integrity(self.parse(self.sealed()), pinned_digest="", environment={})
        self.assertIn("unverifiable seal", str(caught.exception))

    def test_a_stale_pin_is_reported_with_both_digests(self):
        manifest = self.parse(self.bundle(MANIFEST_HEAD))
        report = pm.verify_integrity(manifest, pinned_digest="sha256:" + "0" * 64)
        self.assertFalse(report["ok"])
        self.assertIn(manifest.content_digest, report["reason"])


class PortabilityTests(BundleTestCase):
    def test_the_current_host_profile_describes_the_primitives_we_use(self):
        profile = pm.current_host_profile()
        self.assertIn(profile["name"], ("linux", "darwin", "windows"))
        self.assertIn("flock", profile)

    def test_a_posix_only_bundle_is_refused_on_windows(self):
        manifest = self.parse(self.bundle(MANIFEST_HEAD + '\n[compatibility]\nplatforms = ["posix"]\nrequires_flock = true\n'))
        # The *current* host is linux, so nothing is refused here; the refusal is at install.
        self.assertEqual(pm.check_host_compatibility(manifest), "")
        report = pm.portability_report(manifest, ())
        rows = {row["host"]: row for row in report["hosts"]}
        self.assertTrue(rows["linux"]["fits"])
        self.assertFalse(rows["windows"]["fits"])
        self.assertTrue(any("flock" in reason for reason in rows["windows"]["reasons"]))
        self.assertFalse(report["portable_everywhere"])

    def test_case_insensitive_file_names_are_a_portability_defect(self):
        root = self.bundle(
            MANIFEST_HEAD + '\n[components]\nagents = ["agents"]\n',
            {"agents/A1.md": "---\nname: a\ndescription: d\n---\n\n", "agents/a1.md": "---\nname: b\ndescription: d\n---\n\n"},
        )
        bundle = pm.load_bundle(root)
        manifest = pm.parse_manifest(bundle)
        report = pm.portability_report(manifest, bundle.files)
        self.assertTrue(report["case_collisions"])
        rows = {row["host"]: row for row in report["hosts"]}
        self.assertFalse(rows["windows"]["fits"], "two names differing only by case collide there")
        self.assertTrue(rows["linux"]["fits"], "and are merely confusing on a case-sensitive host")

    def test_a_python_claim_higher_than_the_host_is_refused(self):
        manifest = self.parse(self.bundle(MANIFEST_HEAD + '\n[compatibility]\nmin_python = "9.9"\n'))
        self.assertTrue(pm.portability_report(manifest, ())["hosts"])
        for row in pm.portability_report(manifest, ())["hosts"]:
            self.assertFalse(row["fits"])

    def test_only_hosts_filters_the_display_not_the_verdict(self):
        manifest = self.parse(self.bundle(MANIFEST_HEAD + '\n[compatibility]\nplatforms = ["linux"]\n'))
        report = pm.portability_report(manifest, (), only_hosts=["linux"])
        self.assertEqual([row["host"] for row in report["hosts"]], ["linux"])
        self.assertFalse(report["portable_everywhere"], "darwin/windows still decide the verdict")
        with self.assertRaises(pm.PluginError):
            pm.portability_report(manifest, (), only_hosts=["plan9"])


class ExportTests(BundleTestCase):
    FULL = (
        MANIFEST_HEAD
        + '\n[components]\nskills = ["skills"]\nagents = ["agents"]\n'
        + '[[components.hooks]]\nevent = "PreToolUse"\ntool = "Write"\nscript = "g.py"\n'
        + "[[components.mcp_servers]]\nname = \"srv\"\ncommand = \"mcp-srv\"\n"
        + "[policy]\ndeny_tools = [\"Write\"]\n"
    )

    def full_bundle(self, name: str = "full") -> Path:
        return self.bundle(
            self.FULL,
            {
                "skills/one/SKILL.md": "---\nname: one\ndescription: first skill\n---\n\nDo it.\n",
                "agents/helper.md": "---\nname: helper\ndescription: helps\n---\n\nAssist.\n",
                "g.py": "pass\n",
            },
            name=name,
        )

    def test_every_target_is_renderable_and_names_what_it_cannot_carry(self):
        root = self.full_bundle()
        bundle = pm.load_bundle(root)
        manifest = pm.parse_manifest(bundle)
        declared = pm.declared_components(manifest)
        for target in pm.EXPORT_TARGETS:
            with self.subTest(target=target):
                export = pm.export_bundle(bundle, manifest, target=target)
                self.assertTrue(export.files, f"{target} rendered nothing")
                carried = pm.CARRIED_BY_TARGET[target]
                self.assertEqual(export.dropped, sorted(declared - carried))

    def test_the_drop_list_is_computed_not_written_by_the_renderer(self):
        # A renderer that claimed to carry more than the table says would be a bug the
        # drop list would hide; the assertion is that the list equals the table's opinion.
        root = self.full_bundle()
        bundle = pm.load_bundle(root)
        manifest = pm.parse_manifest(bundle)
        export = pm.export_bundle(bundle, manifest, target="cursor")
        self.assertEqual(export.dropped, ["agents", "hooks", "mcp_servers", "policy"])

    def test_skills_round_trip_byte_for_byte(self):
        root = self.full_bundle()
        bundle = pm.load_bundle(root)
        export = pm.export_bundle(bundle, pm.parse_manifest(bundle), target="skills")
        text = export.files["skills/one/SKILL.md"]
        self.assertIn("name: one", text)
        self.assertIn("Do it.", text)
        self.assertEqual(export.dropped, sorted({"agents", "hooks", "mcp_servers", "policy", "skills"} - {"skills"}))

    def test_an_unknown_target_is_an_error_not_a_fallback(self):
        root = self.full_bundle()
        with self.assertRaises(pm.PluginError) as caught:
            pm.export_bundle(pm.load_bundle(root), pm.parse_manifest(pm.load_bundle(root)), target="vscode")
        self.assertIn("cursor", str(caught.exception), "the refusal has to list what is available")

    def test_export_notes_declare_that_no_other_host_was_exercised(self):
        root = self.full_bundle()
        for target in pm.EXPORT_TARGETS:
            export = pm.export_bundle(pm.load_bundle(root), pm.parse_manifest(pm.load_bundle(root)), target=target)
            self.assertTrue(any("docs" in note or "not" in note for note in export.notes), target)


class ComponentListingTests(BundleTestCase):
    def test_candidates_and_lines_describe_the_same_bundle(self):
        root = self.bundle(
            MANIFEST_HEAD + '\n[components]\nskills = ["skills"]\nagents = ["agents"]\n',
            {"skills/one/SKILL.md": "---\nname: one\ndescription: d\n---\n\n", "agents/helper.md": "---\nname: helper\ndescription: d\n---\n\n"},
        )
        bundle = pm.load_bundle(root)
        manifest = pm.parse_manifest(bundle)
        self.assertEqual([name for name, _ in pm.skill_candidates(bundle, manifest)], ["one"])
        self.assertEqual([path.name for path in pm.agent_files(bundle, manifest)], ["helper.md"])
        described = pm.describe_components(manifest)
        self.assertEqual(described["skills"], ["skills"])
        self.assertNotIn("file_count", described, "a constant reported as a measurement is worse than no field")
        lines = pm.component_lines(manifest)
        self.assertIn("skills: skills", lines)
        self.assertIn("agents: agents", lines)


class MirrorConstantsTests(BundleTestCase):
    """The guardrails a bundle is held to are the workspace's own, not a copy."""

    def test_limits_are_imported_not_mirrored_values(self):
        self.assertEqual(pm.HOOK_EVENTS, command_hooks.VETO_EVENTS)
        self.assertEqual(pm.ALLOWED_INTERPRETERS, command_hooks.ALLOWED_INTERPRETERS)
        self.assertEqual(pm.MAX_HOOKS, command_hooks.MAX_HOOKS)

    def test_the_directory_names_match_the_seams_a_plugin_reuses(self):
        import agent_files
        import skills

        self.assertEqual(pm.PLUGINS_DIRECTORY, ".northstar/plugins")
        self.assertTrue(skills.SKILLS_DIRECTORY.startswith(".northstar/"))
        self.assertTrue(agent_files.AGENTS_DIRECTORY.startswith(".northstar/"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
