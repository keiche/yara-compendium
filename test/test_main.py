import os
import shutil
import stat

import pytest
import yaml

from compendium import main, config


@pytest.fixture()
def ruleset_name():
    return "test_ruleset"


@pytest.fixture()
def rule_file_name():
    return "test.rule"


@pytest.fixture()
def local_rules_path():
    return ".mytest"


@pytest.fixture()
def good_yara_str():
    return "rule test\n{\n  condition:\n    true\n}"


def test_validate_yara_good(good_yara_str, ruleset_name, rule_file_name):
    assert main.validate_yara(good_yara_str, ruleset_name, rule_file_name)


@pytest.mark.parametrize(
    "yara_str", ["invalid", "rule test\n{\n  condition:\n    ext_rule_does_not_exist\n}"]
)
def test_validate_yara_bad(yara_str, ruleset_name, rule_file_name):
    assert not main.validate_yara(yara_str, ruleset_name, rule_file_name)


@pytest.fixture()
def setup_rules_dir(good_yara_str, local_rules_path):
    # Create compendium rules dir
    config.rules_path = local_rules_path
    config.compendium_dir = os.path.join(config.rules_path, "compendium")
    os.makedirs(config.compendium_dir, exist_ok=True)
    yara_rule_file = os.path.join(config.compendium_dir, "test.yara")
    local_yara_rule_file = os.path.join("compendium", "test.yara")
    # Write yara rule
    with open(yara_rule_file, "w") as f:
        f.write(good_yara_str)
    rule_paths = [local_yara_rule_file]
    return rule_paths, yara_rule_file


def test_compile_rules_raw_exists(setup_rules_dir, good_yara_str, ruleset_name):
    # Setup
    rules_path, yara_rule_file = setup_rules_dir

    # Test
    outfile = main.compile_rules(
        rule_paths=rules_path, name=ruleset_name, out_path=config.rules_path
    )
    assert os.path.isfile(outfile)

    # Cleanup
    shutil.rmtree(config.rules_path)


def test_compile_rules_raw_dne(setup_rules_dir, good_yara_str, ruleset_name):
    # Setup
    rules_path, yara_rule_file = setup_rules_dir

    # Test
    outfile = main.compile_rules(
        rule_paths=rules_path, name=ruleset_name, out_path=config.rules_path, keep_uncompiled=False
    )
    assert not os.path.isfile(outfile)

    # Cleanup
    shutil.rmtree(config.rules_path)


def test_compile_rules_compiled_exists(setup_rules_dir, good_yara_str, ruleset_name):
    # Setup
    rules_path, yara_rule_file = setup_rules_dir

    # Test
    outfile = main.compile_rules(
        rule_paths=rules_path, name=ruleset_name, out_path=config.rules_path
    )
    assert os.path.isfile(outfile + "c")

    # Cleanup
    shutil.rmtree(config.rules_path)


def test_load_config_empty():
    # Setup
    config_file = ".test_config.yml"
    with open(config_file, "w") as f:
        f.write(yaml.safe_dump({}))

    # Test
    with pytest.raises(ValueError):
        main.load_config(config_file)

    # Cleanup
    os.remove(config_file)


def test_load_config_replaces():
    # Setup
    config_file = ".test_config.yml"
    with open(config_file, "w") as f:
        f.write(yaml.safe_dump({"indent": 5, "git_repos": [1]}))

    # Test
    config_data = main.load_config(config_file)
    assert config_data["indent"] == 5

    # Cleanup
    os.remove(config_file)


# https://stackoverflow.com/a/4829285
def on_rm_error(func, path, exec_info):
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)


def test_download_ruleset(local_rules_path, ruleset_name):
    try:
        # Setup
        os.makedirs(local_rules_path, exist_ok=True)

        # Test
        main.download_ruleset(
            url="https://github.com/Yara-Rules/rules", name=ruleset_name, local_dir=local_rules_path
        )
        assert os.path.isfile(os.path.join(local_rules_path, ruleset_name, "README.md"))

    finally:
        # Cleanup
        shutil.rmtree(local_rules_path, onerror=on_rm_error)
