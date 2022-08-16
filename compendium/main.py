#!/usr/bin/env python3
"""Yara Compendium"""

# Standard libraries
import argparse
import logging.config
import sys

# Custom libraries
from compendium.objects import CompendiumConfig, Rulesets

logger = logging.getLogger(__package__)
logging.getLogger("plyara.core").setLevel(logging.WARNING)

# pylint: disable=c-extension-no-member, unspecified-encoding


def parse_args(args: list) -> argparse.Namespace:
    """
    Parse cmdline arguments
    :param args: Cmdline arguments
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Yara Compendium",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config", type=str, default="etc/config.yml", help="Configuration file path"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (DEBUG level logs)")
    return parser.parse_args(args)


def process_rulesets(config: CompendiumConfig) -> tuple:
    """
    Process the rule sets and write the output Yara rule(s)
    :param config:
    :return: Written combined Yara files
    """
    rulesets = Rulesets(
        rules_path=config.rules_path,
        modify_path=config.configs["modify"],
        disable_path=config.configs["disable"],
        indent=config.indent,
    )

    for rs in config.git_repos:
        rulesets.add_ruleset(ruleset_config=rs, valid_ext=tuple(config.valid_ext))

    # Write files
    if files := rulesets.write_rule():
        for fn in files:
            logger.info("Wrote file: %s", fn)

    # Cleanup original (unprocessed) rules
    if config.cleanup_raw_rules:
        rulesets.remove_raw_rules()

    # Cleanup raw output rule
    if not config.keep_uncompiled:
        rulesets.remove_uncompiled_rules()

    return files


def main():
    args = parse_args(sys.argv[1:])

    # Set up logging
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    comp_config = CompendiumConfig(str(args.config))
    process_rulesets(comp_config)


if __name__ == "__main__":
    main()
