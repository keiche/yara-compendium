"""Yara compendium objects"""

# Standard libraries
import logging
import os
import os.path
import re
import shutil
from datetime import datetime
from typing import Dict, List

# 3rd party libraries
import plyara
import yara
from git import Repo
from yaml import safe_load

# Custom libraries
from compendium.config import RULE_MAP

logger = logging.getLogger(__package__ + ".objects")

# pylint: disable=c-extension-no-member, unspecified-encoding


class CompendiumConfig:
    def __init__(self, config_path: str):
        """
        Configuration for the compendium
        :param config_path: Path to the YAML file with values to set/override
        """
        # Default values
        self.git_repos = []
        self.rules_path = "./rules"
        self.indent = 4
        self.valid_ext = [".yar", ".yara"]
        self.configs = {
            "modify": "./etc/modify.conf",
            "disable": "./etc/disable.conf",
        }
        self.cleanup_raw_rules = True
        self.keep_uncompiled = True

        self.load_config(config_path)

    def load_config(self, config_path: str) -> None:
        """
        Load the configuration file. Use default values if they are not set in the file.
        :param config_path: Path to the configuration file
        """
        # Load the configuration file
        with open(config_path, "r") as f:
            for k, v in safe_load(f).items():
                if k == "git_repos":
                    for git_repo in v:
                        self.git_repos.append(RulesetConfig(git_repo))
                elif hasattr(self, k):
                    setattr(self, k, v)

        if len(self.git_repos) == 0:
            logger.error("No git repos exist in the config")
            raise ValueError("No git repos exist in the config")


class RulesetConfig:
    def __init__(self, ruleset_params: dict) -> None:
        """
        Configuration for a Ruleset
        :param ruleset_params: Parameters to set
        """
        # Defaults
        self.name = None
        self.url = None
        self.branch = "master"
        self.metadata = None
        self.include_dirs = None
        self.exclude_dirs = None
        self.root_dir = False
        self.sub_dirs = False

        self.load_config(ruleset_params)

    def load_config(self, ruleset_params: dict) -> None:
        """
        Load Yara rule set config
        :param ruleset_params: Parameters
        """
        for k, v in ruleset_params.items():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                logger.warning("Rule set parameter %s is not a valid choice - skipping", k)

        assert self.name
        assert self.url


class Rulesets:
    def __init__(
        self,
        rules_path: str,
        modify_path: str,
        disable_path: str,
        indent=4,
    ):
        # Config parameters
        self.rules_path = rules_path.rstrip("/")
        self.indent = indent

        # Compendium dir
        self.local_compendium_dir = "compendium"
        self.compendium_dir = os.path.join(self.rules_path, self.local_compendium_dir)

        # Alterations
        self.alterations = Alterations(mod_path=modify_path, disable_path=disable_path)

        # All rules
        self.all_rules_list = []
        self.raw_rules_dirs = []

    def add_ruleset(self, ruleset_config: RulesetConfig, valid_ext: tuple = (".yar", ".yara")):
        """
        Download, transform, and compile the Yara signatures
        :param ruleset_config: Rule set config
        :param valid_ext: Valid yara extensions
        :return:
        """
        # Create base rules dir
        os.makedirs(self.compendium_dir, exist_ok=True)

        # Download the rule sets and combine them into a single folder
        self._download_ruleset(
            url=ruleset_config.url,
            name=ruleset_config.name,
            local_dir=self.rules_path,
            branch=ruleset_config.branch,
        )

        # Save ruleset path for cleanup
        root_ruleset_dir = os.path.join(self.rules_path, ruleset_config.name)
        self.raw_rules_dirs.append(root_ruleset_dir)

        # Loop through each directory to find Yara rules
        for ruleset_path in self._get_ruleset_dirs(
            path=root_ruleset_dir,
            include_dirs=ruleset_config.include_dirs if ruleset_config.include_dirs else [],
            exclude_dirs=ruleset_config.exclude_dirs,
            root_dir=ruleset_config.root_dir,
            sub_dirs=ruleset_config.sub_dirs,
        ):
            # Loop through each file in the directory
            for fn in sorted(os.listdir(ruleset_path)):
                fp = os.path.join(ruleset_path, fn)
                # Validate the file exists and has a valid extension
                if os.path.isfile(fp) and any(True for x in valid_ext if fp.endswith(x)):
                    yf = YaraFile(
                        fp,
                        alterations=self.alterations,
                        compendium_dir=self.compendium_dir,
                        indent=self.indent,
                        ruleset_name=ruleset_config.name,
                    )
                    local_final_rule_path = os.path.join(self.local_compendium_dir, fn)
                    final_rule_path = os.path.join(self.compendium_dir, fn)

                    # Copy Yara files directly to the compendium
                    rule_str = yf.file_str
                    if not ruleset_config.metadata:
                        shutil.copy(fp, self.compendium_dir)
                    # Edit the files metadata and then write them to the compendium
                    else:
                        yf.add_meta(ruleset_config.metadata)
                        with open(final_rule_path, "w") as wfp:
                            wfp.write(rule_str)

                    # Validate syntax
                    if not self._validate_yara(rule_str, ruleset_config.name, fn):
                        logger.warning(
                            "Yara Syntax Error - %s in %s ruleset", fn, ruleset_config.name
                        )
                        continue

                    # Add the rule to the overall signature list
                    self.all_rules_list.append(local_final_rule_path)

    def remove_raw_rules(self):
        # Cleanup raw rules
        for raw_dir in self.raw_rules_dirs:
            logger.debug("Removing raw rule dir: %s", raw_dir)
            shutil.rmtree(raw_dir)

    def remove_uncompiled_rules(self):
        logger.debug("Removing uncompiled rules: %s", self.compendium_dir)
        shutil.rmtree(self.compendium_dir)

    @staticmethod
    def _download_ruleset(url: str, name: str, local_dir: str, branch: str) -> None:
        """
        Download Yara rule git repository
        :param url: Git repository URL
        :param name: Name of git repository (to place in a folder)
        :param local_dir: Local path to clone the repository
        :param branch: Git repository branch
        """
        local_repo_path = os.path.join(local_dir.rstrip("/"), name.replace(" ", "_"))

        # Path doesn't exist - clone
        if not os.path.isdir(local_repo_path):
            repo = Repo.clone_from(url=url, to_path=local_repo_path)
            repo.git.checkout(branch)
            logger.debug("Git repo %s cloned to %s", name, local_repo_path)
        # Path exists - pull
        else:
            repo = Repo(local_repo_path)
            repo.git.checkout(branch)
            logger.debug("Git repo %s exists - pulling latest master branch", name)
            origin = repo.remotes.origin
            origin.pull()

    def write_rule(self, name: str = "signatures") -> tuple:
        """
        Create a raw and compiled version of multiple Yara rule files
        :param name: Rule set name
        :return: Raw rule path
        """
        filename = os.path.join(self.rules_path, name.replace(" ", "_") + ".yara")
        filename_c = filename + "c"
        with open(filename, "w") as fp:
            fp.write(f"// {name}\n// Updated {datetime.utcnow()} UTC\n\n")
            for rp in self.all_rules_list:
                fp.write(f'include "{rp}"\n')

        # Save raw and compiled signatures
        rules = yara.compile(filename)
        rules.save(filename_c)
        logger.info("Wrote compiled Yara file: %sc", filename)
        return filename, filename_c

    def _validate_yara(self, rule_str: str, ruleset: str, file_name: str, loop_cnt=0) -> bool:
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
                if ext_ref in RULE_MAP.get(ruleset, ""):
                    rule_str = f'include "{RULE_MAP[ruleset][ext_ref]}"\n{rule_str}'
                    logger.debug(
                        "Adding include file %s to %s and retrying validation", ext_ref, file_name
                    )
                    return self._validate_yara(rule_str, ruleset, file_name, loop_cnt + 1)
                logger.error("No include file found")
            logger.warning(rule_str)
            logger.warning("Error: %s, File: %s", str(e), file_name)
            return False
        return True

    @staticmethod
    def _get_ruleset_dirs(
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
            dirs.append(path)

        # Gather rules in subdirectories
        default_skip_dirs = [".git", ".github"]
        skip_dirs = default_skip_dirs + exclude_dirs if exclude_dirs else default_skip_dirs
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
        compendium_dir: str,
        indent=4,
        ruleset_name=None,
    ) -> None:
        """
        Yara rule file
        :param yara_file: Rule file path
        :param alterations: Modify/disable alterations
        :param indent: Number of spaces to use as indents
        :param ruleset_name: Ruleset name
        """
        # File name
        self.filename = os.path.basename(yara_file)
        self.indent = indent

        # Local file path
        self.compendium_dir = compendium_dir

        # Alterations
        self.alterations = alterations

        # Ruleset name
        self.ruleset_name = ruleset_name

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
            rule_name = rule["rule_name"]
            file_rows.append(f"{scope}rule {rule_name}{tags}")

            # Add rule name to the rule map (used to resolve cross-file references)
            if self.ruleset_name not in RULE_MAP:
                RULE_MAP[self.ruleset_name] = {}
            RULE_MAP[self.ruleset_name][rule_name] = os.path.join(
                self.compendium_dir, self.filename
            )

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
                file_rows.append(f'{" "*self.indent}{condition}')
            # Finish rule contents
            file_rows.append("}")
            file_rows.append("")

        return "\n".join(file_rows)
