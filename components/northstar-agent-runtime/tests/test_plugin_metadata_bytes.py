"""Plugin metadata must consume the same bytes covered by reviewed bundle hashes."""
import unittest
from unittest.mock import patch

import support
import cli
import plugin_load as pl
from agents import builtin_registry
from run_setup import load_workspace_agents
from test_plugin_install import BundleTestCase
from tools import build_default_registry


class PluginMetadataBytesTests(BundleTestCase):
    def args(self):
        return cli.build_parser().parse_args([
            'run', '--workspace', str(self.workspace), '--prompt', 'x',
            '--no-project-context', '--no-memory',
        ])

    def contributions(self):
        return pl.load_contributions(self.workspace, known_tools=build_default_registry().names())

    def test_plugin_skill_metadata_replaced_after_bundle_review_is_refused(self):
        self.install()
        plugins = self.contributions()
        path = self.installed('skills/demo-skill/SKILL.md')
        path.write_text('---\nname: demo-skill\ndescription: INJECTED\n---\nbody\n')
        with self.assertRaises(Exception):
            cli.compose_system_prompt(self.args(), None, None, plugins)

    def test_agent_prompt_replaced_after_bundle_review_is_refused(self):
        self.install()
        plugins = self.contributions()
        path = self.installed('agents/demo-agent.md')
        path.write_text('---\nname: demo-agent\ndescription: demo\ntools: [Read]\n---\nINJECTED_PROMPT\n')
        with self.assertRaisesRegex(cli.RunConfigurationError, 'review'):
            load_workspace_agents(self.args(), builtin_registry(), build_default_registry(), plugins)

    def test_unreviewed_skill_added_after_bundle_review_is_refused(self):
        self.install()
        plugins = self.contributions()
        path = self.installed('skills/new-skill/SKILL.md')
        path.parent.mkdir()
        path.write_text('---\nname: new-skill\ndescription: INJECTED\n---\nbody\n')
        with self.assertRaises(Exception):
            cli.compose_system_prompt(self.args(), None, None, plugins)

    def test_plugin_agent_added_after_bundle_review_is_refused(self):
        self.install()
        plugins = self.contributions()
        self.installed('agents/new-agent.md').write_text(
            '---\nname: new-agent\ndescription: demo\ntools: [Read]\n---\nINJECTED\n')
        with self.assertRaisesRegex(cli.RunConfigurationError, 'review'):
            load_workspace_agents(self.args(), builtin_registry(), build_default_registry(), plugins)

    def test_plugin_hook_changed_after_bundle_review_is_refused(self):
        from run_setup import load_hooks, RunConfigurationError
        self.install()
        plugins = self.contributions()
        hook_file = self.installed('guard.py')
        hook_file.write_text('UNREVIEWED_HOOK_BYTES\n', encoding='utf-8')
        args = self.args()
        args.enable_workspace_hooks = True
        with self.assertRaisesRegex(RunConfigurationError, 'changed since bundle review'):
            load_hooks(args, None, plugins, build_default_registry())

    def test_unchanged_plugin_metadata_and_same_byte_replacement_work(self):
        self.install()
        plugins = self.contributions()
        for relative in ['skills/demo-skill/SKILL.md', 'agents/demo-agent.md']:
            path = self.installed(relative)
            replacement = path.with_suffix('.replacement')
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
        prompt = cli.compose_system_prompt(self.args(), None, None, plugins)
        self.assertEqual([s.name for s in prompt.skills], ['demo-skill'])
        agents = load_workspace_agents(self.args(), builtin_registry(), build_default_registry(), plugins)
        self.assertEqual([a.name for a in agents], ['demo-agent'])


if __name__ == '__main__':
    unittest.main()
