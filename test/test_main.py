import os
import shutil

import pytest
import yaml
from git import Repo

from compendium.main import parse_args, process_rulesets
from compendium.objects import CompendiumConfig, RulesetConfig


@pytest.fixture()
def empty_config_file():
    config_file = ".test_config.yml"
    with open(config_file, "w") as f:
        f.write(yaml.safe_dump({}))
    yield config_file

    # Teardown
    os.remove(config_file)


@pytest.fixture()
def simple_ruleset_config():
    return {"name": "foo", "url": "bar"}


@pytest.fixture()
def indent_config_file(simple_ruleset_config):
    config_file = ".test_config.yml"
    with open(config_file, "w") as f:
        f.write(yaml.safe_dump({"indent": 5, "git_repos": [simple_ruleset_config]}))
    yield config_file

    # Teardown
    os.remove(config_file)


class TestCompendiumConfig:
    def test_load_config_empty(self, empty_config_file):
        with pytest.raises(ValueError):
            CompendiumConfig(empty_config_file)

    def test_load_config_replaces(self, indent_config_file):
        comp_config = CompendiumConfig(indent_config_file)
        assert comp_config.indent == 5


class TestRulesetConfig:
    def test_config(self, simple_ruleset_config):
        rsc = RulesetConfig(simple_ruleset_config)
        assert rsc.name == "foo"
        assert rsc.url == "bar"

    def test_empty_config(self, indent_config_file):
        with pytest.raises(AssertionError):
            RulesetConfig({})


@pytest.fixture()
def input_args():
    return ["-c", "foobar", "-v"]


@pytest.fixture()
def input_args_invalid():
    return ["-x"]


class TestParseArgs:
    def test_parse_args_default(self):
        args = parse_args([])
        assert not args.verbose

    def test_parse_args_set(self, input_args):
        args = parse_args(input_args)
        assert args.verbose
        assert args.config == "foobar"

    def test_parse_args_invalid(self, input_args_invalid):
        with pytest.raises(SystemExit):
            parse_args(input_args_invalid)


@pytest.fixture()
def ruleset_name():
    return "test_ruleset"


@pytest.fixture()
def local_test_path():
    return ".mytest"


@pytest.fixture()
def local_rules_path(local_test_path):
    rules_path = os.path.join(local_test_path, "rules/")
    os.path.join(local_test_path, "compendium/")
    os.makedirs(rules_path, exist_ok=True)
    return rules_path


@pytest.fixture()
def good_yara_str():
    return "rule test\n{\n  condition:\n    true\n}\n"


def create_git_repo(test_path, ruleset_name, yara_str) -> str:
    ext_repo_path = os.path.join(test_path, "ext/", ruleset_name)
    os.makedirs(ext_repo_path, exist_ok=True)

    repo = Repo.init(ext_repo_path)
    yara_rule = os.path.join(ext_repo_path, "test.yara")
    with open(yara_rule, "w") as f:
        f.write(yara_str)
    repo.index.add("test.yara")
    repo.index.commit("committing yara rule")
    repo.create_head("master")
    return ext_repo_path


@pytest.fixture()
def full_config_file(local_test_path, ruleset_name, good_yara_str):
    # Create git repo
    ext_repo_path = create_git_repo(local_test_path, ruleset_name, good_yara_str)

    config_file = ".test_config.yml"
    ruleset_params = {
        "name": "testrules",
        "url": ext_repo_path,
        "root_dir": True,
        "metadata": {"foo": "bar", "baz": 123, "qux": True},
    }
    with open(config_file, "w") as f:
        f.write(yaml.safe_dump({"indent": 2, "git_repos": [ruleset_params]}))
    yield config_file

    # Teardown
    shutil.rmtree(local_test_path)


class TestProcessRulesets:
    def test_process_rulesets(self, full_config_file):
        comp_config = CompendiumConfig(full_config_file)
        files = process_rulesets(comp_config)
        assert len(files) > 0
        for f in files:
            assert os.path.isfile(f)
