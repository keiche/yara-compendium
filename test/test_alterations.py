import os
import shutil
from pathlib import Path

import pytest

from compendium.objects import Alterations


@pytest.fixture()
def local_test_path():
    return ".mytest"


@pytest.fixture()
def local_etc_path(local_test_path):
    # Set up
    etc_path = os.path.join(local_test_path, "etc/")
    os.makedirs(etc_path, exist_ok=True)

    # Resource
    yield etc_path

    # Teardown
    shutil.rmtree(local_test_path)


class TestAlterations:
    @pytest.mark.parametrize(
        "modify_contents", [['rule_name "foo" "bar"'], ['rule1 "foo" "bar"', 'rule2 "bar" "baz"']]
    )
    def test_modify(self, modify_contents, local_etc_path):
        # Create files
        mp = os.path.join(local_etc_path, "modify.conf")
        dp = os.path.join(local_etc_path, "disable.conf")
        with open(mp, "w") as f:
            for line in modify_contents:
                f.write(line + "\n")
        Path(dp).touch()

        # Test
        alterations = Alterations(mod_path=mp, disable_path=dp)
        assert len(alterations.modify) == len(modify_contents)

    def test_modify_no_file(self, local_etc_path, local_test_path):
        # Create files
        dp = os.path.join(local_etc_path, "disable.conf")
        Path(dp).touch()

        # Test
        with pytest.raises(FileNotFoundError):
            Alterations(mod_path="does_not_exist.conf", disable_path=dp)

    @pytest.mark.parametrize(
        "modify_contents",
        [
            ["foobar"],
            ["rule_name 'wrong' 'quotes'", "rule_name no quotes"],
            ["rule_name no quotes"],
        ],
    )
    def test_modify_all_invalid(self, modify_contents, local_etc_path, local_test_path):
        # Create files
        mp = os.path.join(local_etc_path, "modify.conf")
        dp = os.path.join(local_etc_path, "disable.conf")
        with open(mp, "w") as f:
            for line in modify_contents:
                f.write(line + "\n")
        Path(dp).touch()

        # Test
        alterations = Alterations(mod_path=mp, disable_path=dp)
        assert len(alterations.modify) == 0

    @pytest.mark.parametrize("disable_contents", ["disable1", "disable_2"])
    def test_disable(self, disable_contents, local_etc_path, local_test_path):
        # Create files
        mp = os.path.join(local_etc_path, "modify.conf")
        dp = os.path.join(local_etc_path, "disable.conf")
        with open(dp, "w") as f:
            for line in disable_contents:
                f.write(line + "\n")
        Path(mp).touch()

        # Test
        alterations = Alterations(mod_path=mp, disable_path=dp)
        assert len(alterations.disable) == len(disable_contents)

    def test_disable_no_file(self, local_etc_path, local_test_path):
        # Create files
        mp = os.path.join(local_etc_path, "modify.conf")
        Path(mp).touch()

        # Test
        with pytest.raises(FileNotFoundError):
            Alterations(mod_path=mp, disable_path="does_not_exist.conf")
