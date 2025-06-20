#! /usr/bin/env python3
# pip install drain3 tyro
# pip install drain3~="0.9.11" tyro~="0.9.24"
"""
This script computes clusters of similar log lines from the provided log files.
It uses the drain3 library to extract templates from log lines.
It can filter log lines based on a regex pattern and display the clusters
"""
import dataclasses
import logging
import pathlib
import re
import sys
import typing
from collections import namedtuple
from math import ceil, log10
from typing import Annotated

import tyro
from drain3 import TemplateMiner  # type: ignore
from drain3.masking import MaskingInstruction  # type: ignore
from drain3.template_miner_config import TemplateMinerConfig  # type: ignore

logging.basicConfig(
    format="%(asctime)s | %(processName)s - %(threadName)s | %(levelname)s : %(message)s",
    level=logging.INFO,
)
logging.getLogger("drain3").setLevel(logging.WARNING)


@dataclasses.dataclass
class Arguments:
    """
    Use drain algorithm to extract clusters of similar log lines
    from the provided log files.

    Arguments for the log extractor script :
    """

    # logs files paths to process
    logfile_paths: tyro.conf.Positional[tuple[pathlib.Path, ...]]
    # If set, filter input log lines which does not match the regex (re python module syntax).
    # Example: '.*(\| Warning |\| Error ).*'
    filter: Annotated[str, tyro.conf.arg(aliases=["-f"])] = ""
    # If set, does not display the count of each cluster.
    # The clusters will be ordered lexicographically.
    lex_order: Annotated[
        tyro.conf.FlagCreatePairsOff[bool], tyro.conf.arg(aliases=["-l"])
    ] = False
    # Similarity threshold for the template miner to group lines together.
    # A higher value will lead to create more clusters.
    similarity_threshold: Annotated[float, tyro.conf.arg(aliases=["-s"])] = 0.4
    # depth of the tree to build the templates miner,
    # a higher value will lead to create more clusters.
    # The higher the value, the more tokens of the log lines
    # will be considered to build the clusters. Increase this value
    # to make clustering rely on distant tokens.
    tree_depth: Annotated[int, tyro.conf.arg(aliases=["-d"])] = 4

    def __post_init__(self) -> None:
        if self.logfile_paths is None or len(self.logfile_paths) == 0:
            error_message = (
                "No log files provided. Please specify at least one log file."
            )
            logging.error(error_message)
            sys.exit(-2)
        if self.tree_depth < 3:
            error_message = (
                f"The tree depth is set to {self.tree_depth}. Minimum value is 3."
            )
            logging.error(error_message)
            sys.exit(-1)


def create_drain3_cfg(args: Arguments) -> TemplateMinerConfig:
    """
    Create a default configuration for the drain3 template miner.

    Returns:
        TemplateMinerConfig: A configuration object for the drain3 template miner.
    """
    drain3_cfg = TemplateMinerConfig()
    # Add masking instructions to the configuration
    mask_ip = MaskingInstruction(
        r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?=[^A-Za-z0-9])|$)",
        "IP",
    )
    mask_time = MaskingInstruction(r"(\d{2}:\d{2}:\d{2}(.\d+|))", "TIME")
    drain3_cfg.masking_instructions += [mask_ip, mask_time]
    drain3_cfg.drain_sim_th = args.similarity_threshold
    drain3_cfg.drain_depth = args.tree_depth

    return drain3_cfg


def add_log_lines_to_miner(
    template_miner: TemplateMiner,
    logfile_paths: tuple[pathlib.Path, ...],
    regex: typing.Union[re.Pattern[str], None],
) -> int:
    """
    Add log lines from a file to the template miner.

    Args:
        template_miner (TemplateMiner): The template miner instance.
        logfile_path (tuple[pathlib.Path, ...]): Paths to the log files.
        regex (re.Pattern | None): Regex pattern to filter log lines.

    Returns:
        int: The number of lines added to the template miner.
    """
    total_nb_lines = 0
    for logfile_path in logfile_paths:
        with open(logfile_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if regex and not regex.match(line):
                    continue
                total_nb_lines += 1
                template_miner.add_log_message(line)
    return total_nb_lines


def handle_cluster_lex_order(template_miner: TemplateMiner) -> None:
    """
    Display all clusters in lexicographical order.

    Args:
        template_miner (TemplateMiner): the template miner which has been filled with log lines.
    """
    ordered_clusters = [
        cluster.get_template() for cluster in template_miner.drain.clusters
    ]
    ordered_clusters.sort()
    for cluster in ordered_clusters:
        print(f"{cluster}")


def handle_cluster_count_order(template_miner: TemplateMiner) -> int:
    """
    Display all clusters ordered by their size.

    Args:
        template_miner (TemplateMiner): the template miner which has been filled with log lines.

    Returns:
        int: The total number of lines in all clusters.
    """
    ClusterResult = namedtuple("ClusterResult", ["size", "pattern"])
    ordered_clusters = [
        ClusterResult(cluster.size, cluster.get_template())
        for cluster in template_miner.drain.clusters
    ]
    if not ordered_clusters:
        return 0
    ordered_clusters.sort(key=lambda x: x[0], reverse=True)
    margin = ceil(log10(ordered_clusters[0].size))
    total_nb_lines_clusters = 0
    for cluster in ordered_clusters:
        print(f"{str(cluster.size).rjust(margin)} - {cluster.pattern}")
        total_nb_lines_clusters += cluster.size
    return total_nb_lines_clusters


def main(args: Arguments) -> int:
    """
    Extract the cluster templates from the provided log files.

    Args:
        args (Arguments): paths and options for the log extractor

    Returns:
        int: 0 if everything went well
    """
    result = 0
    drain3_cfg = create_drain3_cfg(args)
    template_miner = TemplateMiner(config=drain3_cfg)
    regex = None
    try:
        regex = re.compile(args.filter) if args.filter else None
    except re.error as e:
        logging.error("Invalid regex pattern: %s. Error: %s", args.filter, e)
        return -1

    total_nb_lines = add_log_lines_to_miner(template_miner, args.logfile_paths, regex)

    if args.lex_order:
        handle_cluster_lex_order(template_miner)
    else:
        total_nb_lines_clusters = handle_cluster_count_order(template_miner)
        # sanity check
        if total_nb_lines_clusters != total_nb_lines:
            logging.warning(
                "The number of lines in the clusters (%d) does "
                "not match the total number of lines processed (%d).",
                total_nb_lines_clusters,
                total_nb_lines,
            )
            result = 1

    return result


if __name__ == "__main__":
    cfg = tyro.cli(Arguments)
    sys.exit(main(cfg))
