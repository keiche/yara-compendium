#!/usr/bin/env python3
"""Yara Compendium"""

# Standard libraries
import argparse
import logging.config
import os
import os.path
import re
import shutil
import sys
from copy import deepcopy
from datetime import datetime
from typing import Dict, List

# 3rd party libraries
import plyara
import yara
from git import Repo
from yaml import safe_load

logger = logging.getLogger("yara_compendium")
logging.getLogger("plyara.core").setLevel(logging.WARNING)

# pylint: disable=c-extension-no-member, unspecified-encoding


class Alterations:
    def __init__(self, mod_path, disable_path):
        """
        Logic for editing Yara rules
        :param mod_path: Path to modify.conf
        :param disable_path: Path to disable.conf
        """
        self.modify = self._parse_modify(mod_path)
        self.disable = self._parse_disable(disable_path)

    @staticmethod
    def _parse_modify(path: str) -> Dict:
        """
        Gather the "modify" logic
        :param path: Path to modify.conf
        :return: Rule name (key) with the find/replace logic
        """
        modify = {}
        mod_line_re = re.compile(
            r"^(?P<rule>[a-zA-Z0-9_]+) \"(?P<find>[^\"]+(?=\" \"))\" \"(?P<repl>[^\"]+(?=\"$))\"$"
        )
        with open(path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                if m := mod_line_re.match(line):
                    modify[m.group("rule")] = {"find": m.group("find"), "replace": m.group("repl")}
        return modify

    @staticmethod
    def _parse_disable(path: str) -> List:
        """
        Gather the "disable" rule list
        :param path: Path to disable.conf
        :return: Yara rules to disable
        """
        disable = []
        with open(path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                disable.append(line.rstrip())
        return disable


class YaraFile:
    def __init__(
        self,
        yara_file: str,
        alterations: Alterations,
        indent=4,
        ruleset_name=None,
        prepend_ruleset=False,
    ) -> None:
        """
        Yara rule file
        :param yara_file: Rule file path
        :param alterations: Modify/disable alterations
        :param indent: Number of spaces to use as indents
        :param ruleset_name: Ruleset name
        :param prepend_ruleset: Whether to prepend the ruleset name to each rule
        """
        # File name
        self.filename = os.path.basename(yara_file)
        self.indent = indent

        # Alterations
        self.alterations = alterations

        # Ruleset name
        self.ruleset_name = re.sub(r"[^a-zA-Z0-9]", "_", ruleset_name).lower() + "__"
        self.prepend_ruleset = prepend_ruleset
        self.prev_rule_names = {}

        # Rules
        parser = plyara.Plyara()
        with open(yara_file, "r") as f:
            self.rules = parser.parse_string(f.read())

    def add_meta(self, meta: Dict) -> None:
        """
        Add metadata to each rule. Will overwrite if the metadata field already exists
        :param meta: Metadata fields and values to add
        """
        for i, _ in enumerate(self.rules):
            if "metadata" not in self.rules[i]:
                self.rules[i]["metadata"] = []
            m = [{k: v} for k, v in meta.items()]
            self.rules[i]["metadata"].extend(m)

    def _get_unique_element(self, element) -> List:
        """
        Retrieve the unique elements of a Yara rule
        :param element: Yara element to retrieve
        :return: Yara element values
        """
        elements = set()
        for rules in self.rules:
            for ele in rules.get(element, []):
                elements.add(ele)
        return list(elements)

    @property
    def file_str(self):
        """
        Reconstruct the updated Yara file as a string
        """
        file_rows = []

        # Gather imports and includes
        for verb in ["imports", "includes"]:
            if elements := self._get_unique_element(verb):
                file_rows.extend([f'{verb.rstrip("s")} "{x}"' for x in elements])
            # Add blank line between sections
            if elements:
                file_rows.append("")

        # Create rules
        for rule in self.rules:
            # Modify rule
            if rule["rule_name"] in self.alterations.modify:
                find = self.alterations.modify[rule["rule_name"]]["find"]
                repl = self.alterations.modify[rule["rule_name"]]["replace"]
                logger.debug("Modifying '%s': '%s' with '%s'", rule["rule_name"], find, repl)

                rule["raw_strings"] = re.sub(rf"{find}", rf"{repl}", rule["raw_strings"])
                rule["raw_condition"] = re.sub(rf"{find}", rf"{repl}", rule["raw_condition"])

            # Disable rule
            if rule["rule_name"] in self.alterations.disable:
                logger.debug("Found rule '%s' and skipping due to disable logic", rule["rule_name"])
                continue

            # Rule name and tags
            tags = " ".join(self._get_unique_element("tags"))
            tags = f" : {tags}" if tags else tags
            scope = f'{rule.get("scope", "")} ' if rule.get("scope") else ""
            rule_name = (
                rule["rule_name"]
                if not self.prepend_ruleset
                else f"{self.ruleset_name}{rule['rule_name']}"
            )
            file_rows.append(f"{scope}rule {rule_name}{tags}")

            # Map the name change for usage in the condition
            self.prev_rule_names[rule["rule_name"]] = rule_name

            # Start rule contents
            file_rows.append("{")

            # Add metadata (may have been altered via add_meta)
            if "metadata" in rule:
                file_rows.append(f'{" "*self.indent}meta:')
                for m in rule["metadata"]:
                    for k, v in m.items():
                        if isinstance(v, str):
                            v = f'"{v}"'
                        elif isinstance(v, bool):
                            # Prevent using python syntax for Booleans
                            v = "true" if v else "false"
                        file_rows.append(f'{" "*self.indent*2}{k} = {v}')
                file_rows.append("")

            # Add strings
            if "raw_strings" in rule:
                file_rows.append(f'{" "*self.indent}{rule["raw_strings"]}')
            # Add condition
            if "raw_condition" in rule:
                condition = rule["raw_condition"]
                # If rule names were altered, then update to their new name
                if self.prepend_ruleset:
                    for prev, new in self.prev_rule_names.items():
                        condition = re.sub(rf"\b{prev}\b", new, condition)
                file_rows.append(f'{" "*self.indent}{condition}')
            # Finish rule contents
            file_rows.append("}")
            file_rows.append("")

        return "\n".join(file_rows)


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


def compile_rules(rule_paths: List, name: str, out_path: str, keep_uncompiled=True) -> None:
    """
    Create a raw and compiled version of multiple Yara rule files
    :param rule_paths: List of rule paths to combine
    :param name: Rule set name
    :param out_path: Location to write combined rules
    :param keep_uncompiled: Whether to keep the uncompiled rules
    """
    filename = f'{out_path}/{name.replace(" ", "_")}.yara'
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


def validate_yara(rule_path: str) -> bool:
    """
    Validate the syntax of a yara rule file
    :param rule_path: Path to yara rule
    :return: Valid syntax boolean
    """
    try:
        yara.compile(rule_path)
    except yara.SyntaxError:
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
        logger.error("No repos exist in the config")
        sys.exit(1)

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

    # Setup logging
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    rules_path = config["rules_path"].rstrip("/")
    local_compendium_dir = "compendium"
    compendium_dir = f"{rules_path}/{local_compendium_dir}"
    os.makedirs(compendium_dir, exist_ok=True)

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
            for fn in os.listdir(ruleset_path):
                fp = os.path.join(ruleset_path, fn)
                # Validate the file exists and has a valid extension
                if os.path.isfile(fp) and any(True for x in config["valid_ext"] if fp.endswith(x)):
                    yf = YaraFile(
                        fp,
                        alterations=alterations,
                        indent=config.get("indent", 4),
                        ruleset_name=ruleset_name,
                        prepend_ruleset=ruleset.get("prepend_ruleset", False),
                    )
                    local_final_rule_path = f"{local_compendium_dir}/{fn}"
                    final_rule_path = f"{compendium_dir}/{fn}"

                    # Copy Yara files directly to the compendium
                    if "metadata" not in ruleset:
                        shutil.copy(fp, compendium_dir)
                    # Edit the files metadata and then write them to the compendium
                    else:
                        yf.add_meta(ruleset["metadata"])
                        with open(final_rule_path, "w") as wfp:
                            wfp.write(yf.file_str)

                    # Validate syntax
                    if not validate_yara(final_rule_path):
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
