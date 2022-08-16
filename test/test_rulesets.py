import os
import shutil
from pathlib import Path

import pytest
from git import Repo

from compendium.objects import RulesetConfig, Rulesets


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
def rule_file_name():
    return "test.rule"


@pytest.fixture()
def local_etc_path(local_test_path):
    etc_path = os.path.join(local_test_path, "etc/")
    os.makedirs(etc_path, exist_ok=True)
    return etc_path


@pytest.fixture()
def good_yara_str():
    return "rule test\n{\n  condition:\n    true\n}\n"


@pytest.fixture()
def empty_rulesets(local_rules_path, local_etc_path, local_test_path):
    # Set up
    os.makedirs(local_etc_path, exist_ok=True)
    Path(mp := os.path.join(local_etc_path, "modify.conf")).touch()
    Path(dp := os.path.join(local_etc_path, "disable.conf")).touch()

    # Resource
    yield Rulesets(rules_path=local_rules_path, modify_path=mp, disable_path=dp)

    # Teardown
    shutil.rmtree(local_test_path)


@pytest.fixture()
def good_ruleset(good_yara_str, local_rules_path, local_etc_path, local_test_path):
    # Create compendium rules dir
    os.makedirs(local_etc_path, exist_ok=True)
    os.makedirs(local_rules_path, exist_ok=True)

    yara_rule_file = os.path.join(local_rules_path, "compendium/", "test.yara")
    local_yara_rule_file = os.path.join("compendium", "test.yara")
    # Write yara rule
    with open(yara_rule_file, "w") as f:
        f.write(good_yara_str)
    rule_paths = [local_yara_rule_file]
    yield rule_paths, yara_rule_file

    # Teardown
    shutil.rmtree(local_test_path)


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
def ruleset_config(local_test_path, ruleset_name, good_yara_str):
    ext_repo_path = create_git_repo(local_test_path, ruleset_name, good_yara_str)
    params = {
        "name": ruleset_name,
        "url": ext_repo_path,
        "root_dir": True,
        "metadata": {"foo": "bar"},
    }
    return RulesetConfig(params)


class TestRulesets:
    def test_validate_yara(self, empty_rulesets, good_yara_str, ruleset_name, rule_file_name):
        assert empty_rulesets._validate_yara(good_yara_str, ruleset_name, rule_file_name)

    @pytest.mark.parametrize(
        "yara_str", ["invalid", "rule test\n{\n  condition:\n    ext_rule_does_not_exist\n}\n"]
    )
    def test_validate_yara_invalid(self, empty_rulesets, yara_str, ruleset_name, rule_file_name):
        assert not empty_rulesets._validate_yara(yara_str, ruleset_name, rule_file_name)

    def test_add_ruleset(self, empty_rulesets, ruleset_config, local_rules_path):
        empty_rulesets.add_ruleset(ruleset_config=ruleset_config)
        assert len(empty_rulesets.all_rules_list) > 0

    def test_write_rule(self, empty_rulesets, ruleset_config, local_rules_path, ruleset_name):
        out_rule_name = "signatures"
        empty_rulesets.add_ruleset(ruleset_config=ruleset_config)

        rule_name, rule_name_c = empty_rulesets.write_rule(name="out_rule_name")
        assert os.path.isfile(rule_name)
        assert os.path.isfile(rule_name_c)

        empty_rulesets.remove_raw_rules()
        assert not os.path.isdir(os.path.join(local_rules_path, ruleset_name))

        empty_rulesets.remove_uncompiled_rules()
        assert not os.path.isfile(os.path.join(local_rules_path, f"{out_rule_name}.yara"))
