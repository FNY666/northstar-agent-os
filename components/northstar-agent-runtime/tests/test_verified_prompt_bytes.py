"""Bind reviewed skill metadata and plugin context to the bytes actually consumed."""
import contextlib
import io
import unittest
from unittest.mock import patch

import support
from support import RuntimeTestCase
import cli
import skill_audit
import skill_check
from test_plugin_install import BundleTestCase, MANIFEST
import plugin_load as pl


class ReviewedSkillPromptTests(RuntimeTestCase):
    def test_direct_prompt_requires_captured_pins_when_lock_is_required(self):
        root = self.workspace()
        args = cli.build_parser().parse_args(['run', '--workspace', str(root), '--prompt', 'x',
                                              '--require-skill-lock', '--no-project-context', '--no-memory'])
        with self.assertRaisesRegex(cli.RunConfigurationError, 'captured'):
            cli.compose_system_prompt(args, None, None, None)

    def test_skill_changed_after_lock_check_is_not_used_in_prompt(self):
        self._check_replacement(repin=False)

    def test_replacing_lock_after_check_cannot_change_trusted_pins(self):
        self._check_replacement(repin=True)

    def _check_replacement(self, *, repin):
        root = self.workspace()
        skill = root / '.northstar/skills/demo/SKILL.md'
        skill.parent.mkdir(parents=True)
        skill.write_text('---\nname: demo\ndescription: SAFE_DESCRIPTION\n---\nSafe body\n')
        skill_audit.write_lock(root / '.northstar/skills.lock', skill_audit.audit_tree(root))
        check = skill_check.run_lock_status
        observed = {}
        compose = cli.compose_system_prompt

        def checked_then_replaced(workspace):
            result = check(workspace)
            self.assertTrue(result[0])
            skill.write_text('---\nname: demo\ndescription: INJECTED_DESCRIPTION\n---\nChanged body\n')
            if repin:
                skill_audit.write_lock(root / '.northstar/skills.lock', skill_audit.audit_tree(root))
            return result

        def capture(*args):
            value = compose(*args)
            observed['prompt'] = value.system_prompt or ''
            return value

        with patch.object(skill_check, 'run_lock_status', checked_then_replaced), \
             patch.object(cli, 'compose_system_prompt', capture), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(['run', '--workspace', str(root), '--prompt', 'hello',
                             '--scripted-text', 'ok', '--require-skill-lock', '--dry-run',
                             '--no-project-context', '--no-memory', '--no-plugins', '--no-workspace-agents'])
        self.assertEqual(code, 64)
        self.assertNotIn('INJECTED_DESCRIPTION', observed.get('prompt', ''))


class VerifiedPluginContextTests(BundleTestCase):
    def test_plugin_skills_keep_their_separate_trust_source(self):
        import skills
        self.install()
        contributions = pl.load_contributions(self.workspace, known_tools=['Read', 'Write'])
        discovered = skills.discover_skills(
            self.workspace, extra_roots=[path for _name, path in contributions.skill_roots],
            reviewed_digests={},
        )
        self.assertEqual([skill.name for skill in discovered], ['demo-skill'])

    def test_equivalent_context_path_is_still_verified(self):
        manifest = self.source / 'plugin.toml'
        manifest.write_text(MANIFEST.replace('"NOTES.md"', '"./NOTES.md"'))
        self.install()
        contributions = pl.load_contributions(self.workspace, known_tools=['Read', 'Write'])
        self.assertFalse(contributions.blocked)
        self.assertTrue(contributions.context_blocks)

    def test_context_changed_after_digest_check_is_blocked(self):
        self.install()
        load = pl.load_installed

        def verified_then_replaced(*args, **kwargs):
            value = load(*args, **kwargs)
            self.assertEqual(value[0][0].status, 'pinned')
            self.installed('NOTES.md').write_text('UNREVIEWED_CONTEXT')
            return value

        with patch.object(pl, 'load_installed', verified_then_replaced):
            contributions = pl.load_contributions(self.workspace, known_tools=['Read', 'Write'])
        self.assertTrue(contributions.blocked)
        self.assertNotIn('UNREVIEWED_CONTEXT', str(contributions.context_blocks))


if __name__ == '__main__':
    unittest.main()
