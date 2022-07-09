# Overview

Yara rule aggregation and modification tool.

Inspired by tools used to manage open source NIDS signatures such as [pulledpork](https://github.com/shirkdog/pulledpork) and [suricata-update](https://github.com/OISF/suricata-update)

## Features

* Aggregate Yara rules from multiple remote git repositories into a single file
  * Raw `.yara` and compiled `.yarac`
  * Note: The compiled yara rule can only be used on a system with the same Yara version
* Add `meta` key-value pairs to each Yara rule
* Prepend the ruleset name to each Yara rule to help distinguish its source
* Ability to modify specific rules via regex
* Ability to disable specific rules via rule name

## Output

The script will output several files
* Files
  * `${rule_path}/signatures.yara` and `signatures.yarac` - All signatures compiled into a single file
  * `${rule_path}/[RULESET].yara` and `[RULESET].yarac` - All the signatures from each ruleset compiled into a single file
* Directories
  * `${rule_path}/compendium/` - Holds all the modified Yara rule files in a single directory
  * `${rule_path}/[RULESET]/` - Raw Yara rule files from each ruleset

# Installation

1. Install OS dependencies (Ubuntu)
  ```shell
  apt install gcc git python3 python3-dev libyara8 yara
  ```
3. Install Poetry
  ```shell
  curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -
  ```
3. Config Poetry virtual env
  ```shell
  poetry update
  poetry install
  ```
3. Validate
  ```shell
  poetry run yara_compendium --help
  ```

# Usage

```
usage: yara_compendium.py [-h] [-c CONFIG] [-v]

Yara Compendium

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file path (default: etc/config.yml)
  -v, --verbose         Verbose (DEBUG level logs) (default: False)
```

# Configuration Files

## config.yml

* `git_repos` (list of dictionaries) - Configuration details for each remote git repository to pull Yara signatures from
  * `name` (str) - Arbitrary string of what to name this repository
  * `url` (str) - Link to the remote git repository
  * `branch` (str) - Branch of the git repository to use
  * `sub_dirs` (Boolean) - Whether to look for Yara rules in all subdirectories
  * `root_dir` (Boolean) - Whether to look in the root directory for Yara rules
  * `include_dirs` (list of str)- Specific subdirectories to search for Yara rules
  * `exclude_dirs` (list of str)- Specific subdirectories to exclude searching for Yara rules (requires `sub_dirs` to be `true`)
  * `prepend_ruleset` (Boolean) - Prepend the `name` to each of the Yara rules to help distinguish the source ruleset
  * `metadata` (dict) - Arbitrary key-value pairs to add to the metadata of each Yara rule
    * If a key already exists, this will overwrite the value 
    * Examples: `license`, `source_repo`, `tags`
* `indent` (int) - Number of spaces to use when indenting
* `valid_ext` (list) - Yara rule file extensions to search for
* `rule_path` (str) - Path to save output (will be created if it does not exist)
* `configs` (dict) - Path to the alteration configuration files
  * `modify` (str) - Path to `modify.conf`
  * `disable` (str) - Path to `disable.conf`
* `cleanup_raw_rules` (Boolean) - Whether to delete the raw (git clone) rules when complete
* `keep_uncompiled` (Boolean) - Whether to keep the non `.yarac` files when complete

## modify.conf
Modify specific rules via regular expression

Each line of this file uses the following format:
```
RULENAME "FIND REGEX" "REPLACE STRING"
```

Example
```
is_pe "MZ" "{ 4D 5A }"
```

## disable.conf
Disable specific rules by name. If a disabled rule is referenced in another rule, it will cause a syntax error in the other rule, which will then be skipped from being included.

Each line of this file uses the following format:
```
RULENAME
```

Example
```
is_pe
```

# Example

```
$ poetry run yara_compendium -v
2022-07-08 17:07:04,390 yara_compendium DEBUG: Git repo Example cloned to ./rules/Example
2022-07-08 17:07:04,395 yara_compendium DEBUG: Directories from rule set './rules/Example' to gather Yara rules: ['./rules/Example/malware', './rules/Example/webshells']
2022-07-08 17:07:04,592 yara_compendium WARNING: Syntax Error - bad_example.yar in Example ruleset
2022-07-08 17:07:04,674 yara_compendium INFO: Wrote compiled Yara file: ./rules/Example.yarac
2022-07-08 17:07:05,023 yara_compendium DEBUG: Git repo Example2 cloned to ./rules/Example2
2022-07-08 17:07:05,045 yara_compendium DEBUG: Directories from rule set './rules/Example2' to gather Yara rules: ['./rules/Example']
2022-07-08 17:07:05,100 yara_compendium INFO: Wrote compiled Yara file: ./rules/Example2.yarac
2022-07-08 17:07:55,258 yara_compendium INFO: Wrote compiled Yara file: ./rules/signatures.yarac
```

# Future work

* Allow for rules referenced in different files (`include`) to be understood
* Allow for regular expressions in the `modify.conf` rule name
