"""Yara compendium objects"""

# Standard libraries
import logging
import os
import os.path
import re
from typing import Dict, List

# 3rd party libraries
import plyara

# Custom libraries
from compendium.config import compendium_dir, rule_map

logger = logging.getLogger(__package__ + ".objects")


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
        self, yara_file: str, alterations: Alterations, indent=4, ruleset_name=None
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
            if self.ruleset_name not in rule_map:
                rule_map[self.ruleset_name] = {}
            rule_map[self.ruleset_name][rule_name] = os.path.join(compendium_dir, self.filename)

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
