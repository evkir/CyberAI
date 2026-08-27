"""`cyberai detector eval` — score the injection detector against a corpus.

The published measurement surface for the detector, the way `cyberai bench`
is the published surface for the engine. A precision figure in a document is
worth what the command that reproduces it is worth, so this takes the corpus
path as a required argument: there is no hidden default pointing at a
directory that only exists in a git checkout.

The default report is per subclass. An overall recall figure is true and
nearly useless on its own -- it hides which techniques the detector cannot
see at all, and that is the finding.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cyberai.core.security.eval_corpus import (
    CorpusError,
    Evaluation,
    evaluate,
    label_counts,
    load_corpus,
    render_report,
)
from cyberai.core.security.guard import DEFAULT_THRESHOLD

console = Console()


def _pct(value: float | None) -> str:
    """A rate that was never defined prints as a dash, never as 0.0%."""
    return "[dim]--[/dim]" if value is None else f"{value * 100:.1f}%"


def _render(result: Evaluation, corpus: Path, counts: dict[str, int]) -> None:
    table = Table(title=f"detector @ threshold {result.threshold}")
    table.add_column("subclass")
    table.add_column("n", justify="right")
    table.add_column("flagged", justify="right")
    table.add_column("precision", justify="right")
    table.add_column("recall", justify="right")
    table.add_column("FP rate", justify="right")

    for name, cell in sorted(result.by_subclass.items()):
        flagged = cell.true_positive + cell.false_positive
        blind = cell.true_positive == 0 and cell.false_negative > 0
        label = f"[red]{name}[/red]" if blind else name
        # A slice with no positives has no precision to report. Printing 0.0%
        # there would read as "it fired and was always wrong" on a subclass of
        # captured tool output that contains nothing to be right about.
        precision = _pct(cell.precision) if cell.has_positives else "[dim]--[/dim]"
        table.add_row(
            label,
            str(cell.total),
            str(flagged),
            precision,
            _pct(cell.recall),
            _pct(cell.false_positive_rate),
        )

    overall = result.overall
    table.add_section()
    table.add_row(
        "[bold]overall[/bold]",
        str(overall.total),
        str(overall.true_positive + overall.false_positive),
        _pct(overall.precision),
        _pct(overall.recall),
        _pct(overall.false_positive_rate),
    )
    console.print(table)

    console.print(
        f"[dim]corpus {corpus} — {counts['injection']} injections, {counts['benign']} benign[/dim]"
    )
    console.print(
        f"[dim]TP {overall.true_positive}  FN {overall.false_negative}  "
        f"FP {overall.false_positive}  TN {overall.true_negative}  "
        f"F1 {_pct(overall.f1)}[/dim]"
    )

    blind = result.blind_subclasses()
    if blind:
        console.print(
            f"[bold red]blind:[/bold red] {', '.join(blind)} "
            f"[dim]— every sample in these scored below the threshold[/dim]"
        )


@click.group()
def detector() -> None:
    """Measure the prompt-injection detector.

    \b
    Examples:
      cyberai detector eval --corpus tests/corpus
      cyberai detector eval --corpus tests/corpus --threshold 25
      cyberai detector eval --corpus tests/corpus --json > baseline.json
      cyberai detector eval --corpus tests/corpus --report examples/detector-eval/baseline.md
    """


@detector.command("eval")
@click.option(
    "--corpus",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Corpus directory holding manifest.jsonl",
)
@click.option(
    "--threshold",
    type=int,
    default=DEFAULT_THRESHOLD,
    show_default=True,
    help="Score at or above which a sample counts as flagged",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON")
@click.option(
    "--report",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help="Write the Markdown report here. This is how the committed artifact "
    "is produced: never edit it by hand, re-run instead.",
)
def detector_eval(corpus: Path, threshold: int, as_json: bool, report: Path | None) -> None:
    """Score every sample in CORPUS and report precision and recall."""
    try:
        samples = load_corpus(corpus)
    except CorpusError as exc:
        raise click.ClickException(str(exc)) from exc

    result = evaluate(samples, threshold=threshold)
    counts = label_counts(samples)

    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(render_report(result, corpus, counts), encoding="utf-8")
        console.print(f"[green]report written:[/green] {report}")

    if as_json:
        payload = result.as_dict()
        payload["corpus"] = str(corpus)
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    _render(result, corpus, counts)
