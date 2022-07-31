#!/usr/bin/env python3
"""Yara Compendium"""

# Standard libraries
import argparse
import logging.config
import os
import os.path
import re
import shutil
from copy import deepcopy
from datetime import datetime
from typing import Dict, List

# 3rd party libraries
import yara
from git import Repo
from yaml import safe_load

# Custom libraries
from compendium.config import rule_map
from compendium.objects import Alterations, YaraFile

logger = logging.getLogger(__package__)
logging.getLogger("plyara.core").setLevel(logging.WARNING)

# pylint: disable=c-extension-no-member, unspecified-encoding


def download_ruleset(url: str, name: str, local_dir: str) -> None:
    """
    Download Yara rule git repository
    :param url: Git repository URL
    :param name: Name of git repository (to place in a folder)
    :param local_dir: Local path to clone the repository
    """
    local_repo_path = f'{local_dir.rstrip("/")}/{name.replace(" ", "_")}'

    # Path doesn't exist - clone
    if not os.path.isdir(local_repo_path):
        Repo.clone_from(url=url, to_path=local_repo_path)
        logger.debug("Git repo %s cloned to %s}", name, local_repo_path)
    # Path exists - pull
    else:
        repo = Repo(local_repo_path)
        logger.debug("Git repo %s exists - pulling latest master branch", name)
        origin = repo.remotes.origin
        origin.pull()


def compile_rules(rule_paths: List, name: str, out_path: str, keep_uncompiled=True) -> str:
    """
    Create a raw and compiled version of multiple Yara rule files
    :param rule_paths: List of rule paths to combine
    :param name: Rule set name
    :param out_path: Location to write combined rules
    :param keep_uncompiled: Whether to keep the uncompiled rules
    :return: Raw rule path
    """
    filename = os.path.join(out_path, name.replace(" ", "_") + ".yara")
    with open(filename, "w") as fp:
        fp.write(f"// {name}\n// Updated {datetime.utcnow()} UTC\n\n")
        for rp in rule_paths:
            fp.write(f'include "{rp}"\n')

    # Save raw and compiled signatures
    rules = yara.compile(filename)
    rules.save(f"{filename}c")
    logger.info("Wrote compiled Yara file: %sc", filename)
    if not keep_uncompiled:
        logger.debug("Deleting uncompiled version: %s", filename)
        os.remove(filename)
    return filename


def validate_yara(rule_str: str, ruleset: str, file_name: str, loop_cnt=0) -> bool:
    """
    Validate the syntax of a yara rule file
    :param rule_str: Rule file as a string
    :param ruleset: Ruleset name (used for cross-reference resolution)
    :param file_name: File name (used for debugging)
    :param loop_cnt: Loop count (prevent infinite looping)
    :return: Valid syntax boolean
    """
    try:
        yara.compile(source=rule_str)
    except yara.SyntaxError as e:
        # Check if the error is related to an "include" and try to resolve
        if (
            m := re.search(r'undefined identifier "(?P<ext_ref>[^"]+)"', str(e))
        ) is not None and loop_cnt <= 1:
            ext_ref = m.group("ext_ref")
            if ext_ref in rule_map.get(ruleset, ""):
                rule_str = f'include "{rule_map[ruleset][ext_ref]}"\n{rule_str}'
                logger.debug(
                    "Adding include file %s to %s and retrying validation", ext_ref, file_name
                )
                return validate_yara(rule_str, ruleset, file_name, loop_cnt + 1)
            else:
                logger.error("No include file found")
        logger.warning(rule_str)
        logger.warning("Error: %s, File: %s", str(e), file_name)
        return False
    return True


def load_config(config_path: str) -> Dict:
    """
    Load the configuration file. Use default values if they are not set in the file.
    :param config_path: Path to the configuration file
    :return: Configuration dictionary
    """
    default_config = {
        "git_repos": [],
        "rules_path": "./rules",
        "indent": 4,
        "valid_ext": [".yar", ".yara"],
        "configs": {
            "modify": "./etc/modify.conf",
            "disable": "./etc/disable.conf",
        },
        "cleanup_raw_rules": True,
        "keep_uncompiled": True,
    }
    config = deepcopy(default_config)

    # Load the configuration file
    with open(config_path, "r") as f:
        for k, v in safe_load(f).items():
            if k in default_config:
                config[k] = v

    if not len(config["git_repos"]) > 0:
        logger.error("No git repos exist in the config")
        raise ValueError("No git repos exist in the config")

    logger.debug("Config params: %s", config)
    return config


def get_ruleset_dirs(
    path: str, include_dirs: List, exclude_dirs: List, root_dir=False, sub_dirs=True
) -> List:
    """
    Get the directories that should be searched for Yara rules
    :param path: rule set directory
    :param include_dirs: List of subdirectories to include (does not need sub_dirs to also be set)
    :param exclude_dirs: List of subdirectories to exclude (needs sub_dirs to also be set)
    :param root_dir: Whether to include the top level directory
    :param sub_dirs: Whether to include all subdirectories (limited if include_dirs is also set)
    :return: Directories to be searched for Yara rules
    """
    dirs = []

    # Gather rules in the top level directory
    if root_dir:
        dirs.append(["."])

    # Gather rules in subdirectories
    skip_dirs = [".git", ".github"] + exclude_dirs
    if sub_dirs or include_dirs:
        dirs = []
        for f in os.listdir(path):
            if os.path.isdir(sub_dir := os.path.join(path, f)) and sub_dir not in skip_dirs:
                if include_dirs and sub_dir.split("/")[-1] in include_dirs:
                    dirs.append(sub_dir)
                if not include_dirs:
                    dirs.append(sub_dir)
    logger.debug("Directories from rule set '%s' to gather Yara rules: %s", path, dirs)
    return dirs


def main():
    parser = argparse.ArgumentParser(
        description="Yara Compendium",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config", type=str, default="etc/config.yml", help="Configuration file path"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (DEBUG level logs)")
    args = parser.parse_args()

    # Config files
    config = load_config(args.config)
    keep_uncompiled = config.get("keep_uncompiled", True)

    # Set up logging
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # Create base rules dir
    rules_path = config["rules_path"].rstrip("/")
    local_compendium_dir = "compendium"
    compendium_dir = os.path.join(rules_path, local_compendium_dir)
    os.makedirs(compendium_dir, exist_ok=True)

    # Set up the alterations class
    alterations = Alterations(
        mod_path=config["configs"]["modify"], disable_path=config["configs"]["disable"]
    )

    # List of all rule paths for all_sigs.yara
    all_rules_list = []
    raw_rules_dirs = []

    # Download the rule sets and combine them into a single folder
    for ruleset in config.get("git_repos"):
        rules_list = []
        ruleset_name = ruleset["name"]
        download_ruleset(url=ruleset["url"], name=ruleset_name, local_dir=rules_path)

        # Save ruleset path for cleanup
        root_ruleset_dir = os.path.join(rules_path, ruleset_name)
        raw_rules_dirs.append(root_ruleset_dir)

        # Loop through each directory to find Yara rules
        for ruleset_path in get_ruleset_dirs(
            path=root_ruleset_dir,
            include_dirs=ruleset.get("include_dirs", []),
            exclude_dirs=ruleset.get("exclude_dirs", []),
            root_dir=ruleset.get("root_dir", False),
            sub_dirs=ruleset.get("sub_dirs", False),
        ):
            # Loop through each file in the directory
            for fn in sorted(os.listdir(ruleset_path)):
                fp = os.path.join(ruleset_path, fn)
                # Validate the file exists and has a valid extension
                if os.path.isfile(fp) and any(True for x in config["valid_ext"] if fp.endswith(x)):
                    yf = YaraFile(
                        fp,
                        alterations=alterations,
                        indent=config.get("indent", 4),
                        ruleset_name=ruleset_name,
                    )
                    local_final_rule_path = os.path.join(local_compendium_dir, fn)
                    final_rule_path = os.path.join(compendium_dir, fn)

                    # Copy Yara files directly to the compendium
                    rule_str = yf.file_str
                    if "metadata" not in ruleset:
                        shutil.copy(fp, compendium_dir)
                    # Edit the files metadata and then write them to the compendium
                    else:
                        yf.add_meta(ruleset["metadata"])
                        with open(final_rule_path, "w") as wfp:
                            wfp.write(rule_str)

                    # Validate syntax
                    if not validate_yara(rule_str, ruleset_name, fn):
                        logger.warning("Yara Syntax Error - %s in %s ruleset", fn, ruleset_name)
                        continue

                    # Add the rule to the overall signature file(s)
                    all_rules_list.append(local_final_rule_path)
                    rules_list.append(local_final_rule_path)
        # Write the combined rule set
        compile_rules(rules_list, ruleset_name, rules_path, keep_uncompiled)

    # Write the combined rule set for ALL rules
    compile_rules(all_rules_list, "signatures", rules_path, keep_uncompiled)

    # Cleanup raw rules
    if config.get("cleanup_raw_rules", False):
        for raw_dir in raw_rules_dirs:
            logger.debug("Removing raw rule dir: %s", raw_dir)
            shutil.rmtree(raw_dir)

    if not keep_uncompiled:
        logger.debug("Removing uncompiled rules: %s", compendium_dir)
        shutil.rmtree(compendium_dir)


if __name__ == "__main__":
    main()
