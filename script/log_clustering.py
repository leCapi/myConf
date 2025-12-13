#! /usr/bin/env python3
# pip install drain3 tyro
# pip install drain3~="0.9" tyro~="0.9" rich~="14.2"
"""
This script computes clusters of similar log lines from the provided log files.
It uses the drain3 library to extract templates from log lines.
It can filter log lines based on a regex pattern and display the clusters.
"""
import dataclasses
import itertools
import logging
import pathlib
import re
import sys
import time
import typing
from collections import Counter, namedtuple
from math import ceil, log10
from typing import Annotated

import tyro
from drain3 import TemplateMiner  # type: ignore
from drain3.masking import MaskingInstruction  # type: ignore
from drain3.template_miner_config import TemplateMinerConfig  # type: ignore
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.table import Table

error_console = Console(file=sys.stderr, stderr=True)
console = Console()

logging.basicConfig(
    format="%(module)s : %(message)s",
    datefmt="%H:%M:%S.%f",
    level=logging.INFO,
    handlers=[RichHandler(console=error_console)],
)
logging.getLogger("drain3").setLevel(logging.WARNING)

HOME_CFG_FILE = pathlib.Path.home() / ".drain3.ini"
KB_FACTOR = 1000


@dataclasses.dataclass
class Arguments:
    """
    Use drain algorithm to cluster similar log lines
    from the provided log files.

    Arguments for the log clustering script :
    """

    # logs files paths to process
    logfile_paths: tyro.conf.Positional[tuple[pathlib.Path, ...]]
    # configuration file for the drain3 template miner.
    cfg_file: Annotated[pathlib.Path, tyro.conf.arg(aliases=["-c"])] = HOME_CFG_FILE

    # If set, filter input log lines which does not match the regex (re python module syntax).
    # Example: '.*(\| Warning |\| Error ).*'
    filter: Annotated[str, tyro.conf.arg(aliases=["-f"])] = ""
    # If set, the clusters will be ordered lexicographically.
    lex_order: Annotated[
        tyro.conf.FlagCreatePairsOff[bool], tyro.conf.arg(aliases=["-l"])
    ] = False
    # The clusters will be ordered by this total length. Where total length is the sum of all
    # log lines lengths belonging to the cluster.
    size_order: Annotated[
        tyro.conf.FlagCreatePairsOff[bool], tyro.conf.arg(aliases=["-z"])
    ] = False
    # Similarity threshold for the template miner to group lines together.
    # A higher value will lead to create more clusters. Drain default value is 0.4.
    similarity_threshold: Annotated[
        typing.Union[float, None], tyro.conf.arg(aliases=["-s"])
    ] = None
    # depth of the tree to build the templates miner,
    # a higher value will lead to create more clusters.
    # The higher the value, the more tokens of the log lines
    # will be considered to build the clusters. Increase this value
    # to make clustering rely on distant tokens. Drain default value is 4.
    tree_depth: Annotated[
        typing.Union[int, None], tyro.conf.arg(aliases=["-d"], default=4)
    ] = None
    # If set, output clusters in plain text format without colors or table formatting,
    # making it easy to process with bash tools like grep, awk, or cut.
    raw: Annotated[
        tyro.conf.FlagCreatePairsOff[bool], tyro.conf.arg(aliases=["-r"])
    ] = False

    def __post_init__(self) -> None:
        if self.logfile_paths is None or len(self.logfile_paths) == 0:
            error_message = (
                "No log files provided. Please specify at least one log file."
            )
            logging.critical(error_message)
            sys.exit(-2)
        if self.tree_depth and self.tree_depth < 3:
            error_message = (
                f"The tree depth is set to {self.tree_depth}. Minimum value is 3."
            )
            logging.critical(error_message)
            sys.exit(-1)


def create_drain3_cfg(args: Arguments) -> TemplateMinerConfig:
    """
    Create a default configuration for the drain3 template miner.

    Returns:
        TemplateMinerConfig: A configuration object for the drain3 template miner.
    """
    drain3_cfg = TemplateMinerConfig()
    if args.cfg_file.exists():
        logging.info("Loading configuration from %s", args.cfg_file)
        drain3_cfg.load(args.cfg_file)
    else:
        logging.info(
            "Configuration file %s not found. Using default configuration.",
            args.cfg_file,
        )
        mask_time = MaskingInstruction(r"(\d{2}:\d{2}:\d{2}(.\d+|))", "TIME")
        mask_ip = MaskingInstruction(
            r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?=[^A-Za-z0-9])|$)",
            "IP",
        )
        mask_hex = MaskingInstruction(
            r"((?<=[^A-Za-z0-9])|^)(0[xX][0-9a-fA-F]+)((?=[^A-Za-z0-9])|$)",
            "HEX",
        )
        # Add masking instructions to the configuration
        drain3_cfg.masking_instructions += [mask_time, mask_ip, mask_hex]

    if args.similarity_threshold:
        drain3_cfg.drain_sim_th = args.similarity_threshold
    if args.tree_depth:
        drain3_cfg.drain_depth = args.tree_depth
    return drain3_cfg


def estimate_lines(path: pathlib.Path, sample_lines: int = 1000) -> int:
    """
    Estimate total lines based on file size and sample average.
    Args:
        path (pathlib.Path): Path to the log file.
        sample_lines (int): Number of lines to sample for average calculation.
    """
    file_size = path.stat().st_size
    if file_size == 0:
        return 0
    # Sample first 'sample_lines' to get avg bytes per line
    avg_bytes_per_line = 0
    with open(path, "rb") as f:  # Use binary for accurate byte counting
        for i, line in enumerate(f):
            if i >= sample_lines:
                break
            avg_bytes_per_line += len(line)
    if sample_lines > 0:
        avg_bytes_per_line /= sample_lines
    # Estimate total lines
    estimated = int(file_size / avg_bytes_per_line) if avg_bytes_per_line > 0 else 0
    return max(estimated, 1)


def create_file_line_generators(
    logfile_paths: tuple[pathlib.Path, ...],
    progress: Progress,
) -> typing.Generator[str, None, None]:
    """
    Create progress tasks for all files and return a chained generator yielding lines from all files.

    Args:
        logfile_paths (tuple[pathlib.Path, ...]): Paths to the log files.
        progress (Progress): The progress instance to track file processing.

    Returns:
        Generator: A single generator yielding lines from all files.
    """
    generators = []
    for logfile_path in logfile_paths:
        sample_nb_lines = 20000
        number_of_lines = estimate_lines(logfile_path, sample_nb_lines)
        task_id = progress.add_task(
            f"{pathlib.Path(logfile_path).name}", total=number_of_lines
        )

        def line_generator(
            path: pathlib.Path, tid: int, nb_lines: int
        ) -> typing.Generator[str, None, None]:
            """Generator that yields lines from a file and updates progress."""
            with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
                for line in f:
                    progress.update(tid, advance=1)
                    yield line
            progress.update(tid, completed=nb_lines)
            progress.stop_task(tid)

        generators.append(line_generator(logfile_path, task_id, number_of_lines))

    # Chain all generators into one
    return itertools.chain(*generators)


def add_log_lines_to_miner(
    template_miner: TemplateMiner,
    line_generator: typing.Generator[str, None, None],
    regex: typing.Union[re.Pattern[str], None],
) -> tuple[int, Counter]:
    """
    Add log lines from a generator to the template miner.

    Args:
        template_miner (TemplateMiner): The template miner instance.
        line_generator (Generator): A generator yielding log lines.
        regex (re.Pattern | None): Regex pattern to filter log lines.

    Returns:
        tuple[int, Counter]: The number of lines added and cluster sizes counter.
    """
    start_time = time.perf_counter()
    total_nb_lines = 0
    cluster_char_sizes = Counter()

    for line in line_generator:
        if not line:
            continue
        if regex and not regex.match(line):
            continue
        total_nb_lines += 1
        result = template_miner.add_log_message(line)
        cluster_char_sizes[result["cluster_id"]] += len(line)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    logging.info(
        "Processed %d lines in %.2f seconds (%.2f lines/second).",
        total_nb_lines,
        elapsed_time,
        total_nb_lines / elapsed_time if elapsed_time > 0 else 0,
    )
    return total_nb_lines, cluster_char_sizes


def surrogate_non_printable(s: str) -> str:
    """
    Surrogate non-printable characters from a string.

    Args:
        s (str): The input string.
    Returns:
        str: The cleaned string.
    """
    return s.encode("utf-8", errors="surrogateescape").decode("utf-8")


def compute_margin_for_display(max_number: int) -> int:
    """
    Compute the margin for displaying numbers.

    Args:
        max_number (int): The maximum number to display.
    Returns:
        int: The computed margin.
    """
    b10 = log10(max_number)
    margin = ceil(log10(max_number)) if b10 != int(b10) else b10 + 1
    return margin


def display_clusters(
    template_miner: TemplateMiner,
    cluster_char_sizes: Counter,
    order_by: str = "count",
    raw: bool = False,
) -> int:
    """
    Display all clusters in a table with 3 columns: Count - Char Size (KB) - Template.

    Args:
        template_miner (TemplateMiner): the template miner which has been filled with log lines.
        cluster_char_sizes (Counter): a counter of the total sizes of each cluster.
        order_by (str): How to order clusters: "count", "size", or "template". Defaults to "count".

    Returns:
        int: The total number of lines in all clusters.
    """
    ClusterResult = namedtuple("ClusterResult", ["count", "char_size", "template"])
    clusters_data = [
        ClusterResult(
            count=cluster.size,
            char_size=cluster_char_sizes[cluster.cluster_id],
            template=cluster.get_template(),
        )
        for cluster in template_miner.drain.clusters
    ]

    if not clusters_data:
        return 0

    # Sort based on order_by parameter
    if order_by == "size":
        clusters_data.sort(key=lambda x: x.char_size, reverse=True)
    elif order_by == "template":
        clusters_data.sort(key=lambda x: x.template)
    else:  # default to "count"
        clusters_data.sort(key=lambda x: x.count, reverse=True)

    # Add rows to the table or print plain text
    total_nb_lines_clusters = 0
    if raw:
        # Plain text output for bash processing
        count_margin = compute_margin_for_display(
            max(cluster.count for cluster in clusters_data)
        )
        size_margin = compute_margin_for_display(
            max(cluster.char_size for cluster in clusters_data) // KB_FACTOR
        )
        for cluster in clusters_data:
            pattern = surrogate_non_printable(cluster.template)
            count_str = f"{cluster.count}"
            size_kb = cluster.char_size // KB_FACTOR
            size_str = f"{size_kb}"
            console.print(
                f"{count_str:>{count_margin}} - {size_str:>{size_margin}} - {pattern}",
                soft_wrap=True,
            )
            total_nb_lines_clusters += cluster.count
    else:
        # Create a Rich table
        table = Table(title="Log Clusters", highlight=True)
        table.add_column("Count", justify="right", style="cyan", no_wrap=True)
        table.add_column(
            "Char Size (KB)", justify="right", style="magenta", no_wrap=True
        )
        table.add_column("Template", justify="left")

        for cluster in clusters_data:
            pattern = surrogate_non_printable(cluster.template)
            count_str = f"{cluster.count:,}".replace(",", " ")
            size_kb = cluster.char_size // KB_FACTOR
            size_str = f"{size_kb:,}".replace(",", " ")
            table.add_row(count_str, size_str, pattern)
            total_nb_lines_clusters += cluster.count

        # Print the table
        console.print(table, markup=False)

    return total_nb_lines_clusters


def main(args: Arguments) -> int:
    """
    Extract the cluster templates from the provided log files.

    Args:
        args (Arguments): paths and options for the log extractor

    Returns:
        int: 0 if everything went well
    """
    drain3_cfg = create_drain3_cfg(args)
    template_miner = TemplateMiner(config=drain3_cfg)
    regex = None
    try:
        regex = re.compile(args.filter) if args.filter else None
    except re.error as e:
        logging.critical("Invalid regex pattern: %s. Error: %s", args.filter, e)
        return -1
    total_nb_lines, cluster_char_sizes = 0, None
    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=error_console,
        ) as progress:
            line_generator = create_file_line_generators(args.logfile_paths, progress)
            total_nb_lines, cluster_char_sizes = add_log_lines_to_miner(
                template_miner, line_generator, regex
            )
    except FileNotFoundError as e:
        logging.critical("File not found: %s", e.filename)
        return -1
    except IOError as e:
        logging.critical("I/O error(%s): %s", e.errno, e.strerror)
        return -1

    def display_results() -> None:
        order = "count"
        if args.lex_order:
            order = "template"
        elif args.size_order:
            order = "size"
        total_nb_lines_clusters = display_clusters(
            template_miner, cluster_char_sizes, order_by=order, raw=args.raw
        )
        return total_nb_lines_clusters

    def sanity_check(total_nb_lines_clusters: int) -> None:
        """Check if the total number of lines in clusters matches the processed lines."""
        result = 0
        if total_nb_lines_clusters != total_nb_lines:
            logging.error(
                "The number of lines in the clusters (%d) does "
                "not match the total number of lines processed (%d)."
                "Maybe you should increase [DRAIN]/max_clusters parameter.",
                total_nb_lines_clusters,
                total_nb_lines,
            )
            result = 1
        return result

    total_nb_lines_clusters = display_results()
    return sanity_check(total_nb_lines_clusters)


if __name__ == "__main__":
    try:
        cfg = tyro.cli(Arguments)
        sys.exit(main(cfg))
    except KeyboardInterrupt:
        error_console.print("\n[red]Process interrupted by user[/red]")
        sys.exit(-1)
