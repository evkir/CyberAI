"""Score the injection detector against a labelled corpus.

The detector's threshold and its default policy were once chosen on a corpus
that no longer exists. This module is the other half of the fix: the corpus
is tracked in the repository, and this reads it and reports what the detector
does on it, so a published precision figure is a command anyone can re-run
rather than a number in a docstring.

The corpus layout is two directories of samples and a JSONL manifest naming
each one. Metadata lives outside the samples because an HTML comment, an
escape sequence and a ${...} placeholder are three of the detector's own
categories: a front-matter header inside a sample would change the thing
being measured.

Aggregate figures are reported per subclass as well as overall. "Recall 25%"
is true and nearly useless on its own; it hides that five techniques score
zero on every sample they contain, which is the whole argument for a layer
that is not a regex. A caller that only prints the headline is throwing away
the finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence

from cyberai.core.security.injection_detector import l1_scorer
from cyberai.version import __version__

INJECTION = "injection"
BENIGN = "benign"
LABELS = (INJECTION, BENIGN)

# Fields a manifest line must carry to be usable. Provenance fields
# (captured_at, origin) are validated by the corpus's own architecture test,
# not here: this module scores what it is given and reports what it could not
# read, rather than refusing to run on a corpus with a thin entry.
REQUIRED_FIELDS = ("id", "path", "label", "subclass")


class CorpusError(ValueError):
    """The corpus could not be read as a corpus."""


@dataclass(frozen=True)
class Sample:
    """One labelled piece of text and where it came from."""

    id: str
    path: Path
    label: str
    subclass: str
    text: str

    @property
    def is_injection(self) -> bool:
        return self.label == INJECTION


@dataclass
class Counts:
    """The four cells of a confusion matrix for one slice of the corpus."""

    true_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    false_positive: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.false_negative + self.true_negative + self.false_positive

    @property
    def precision(self) -> float | None:
        """None, not zero, when nothing was flagged at all.

        A slice where the detector never fires has no precision: the question
        "of the things it flagged, how many were right" has no subject. Zero
        would read as "it flagged things and every one was wrong", which is a
        different and much worse result.
        """
        flagged = self.true_positive + self.false_positive
        return self.true_positive / flagged if flagged else None

    @property
    def recall(self) -> float | None:
        """None when the slice holds no positives to recall."""
        positives = self.true_positive + self.false_negative
        return self.true_positive / positives if positives else None

    @property
    def false_positive_rate(self) -> float | None:
        """Of the negatives in this slice, the fraction that was flagged.

        None when the slice holds no negatives. This is the figure that
        matters for a slice of captured tool output, where precision has no
        referent: a subclass containing only benign samples has no true
        positives to be precise about, and reporting 0.0% precision there
        reads as "it was always wrong" rather than "the question does not
        apply".
        """
        negatives = self.true_negative + self.false_positive
        return self.false_positive / negatives if negatives else None

    @property
    def has_positives(self) -> bool:
        """Whether asking about precision and recall means anything here."""
        return (self.true_positive + self.false_negative) > 0

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class Evaluation:
    """What the detector did on one corpus at one threshold."""

    threshold: int
    overall: Counts
    by_subclass: Dict[str, Counts] = field(default_factory=dict)
    scores: Dict[str, int] = field(default_factory=dict)
    unreadable: List[str] = field(default_factory=list)

    def blind_subclasses(self) -> List[str]:
        """Subclasses of injections where nothing was ever flagged.

        The headline number cannot show this and it is the most actionable
        thing the evaluation produces.
        """
        return sorted(
            name
            for name, counts in self.by_subclass.items()
            if counts.true_positive + counts.false_negative > 0 and counts.true_positive == 0
        )

    def as_dict(self) -> Dict[str, object]:
        """A shape stable enough to diff between runs and paste into a report."""

        def cell(counts: Counts) -> Dict[str, object]:
            return {
                "total": counts.total,
                "true_positive": counts.true_positive,
                "false_negative": counts.false_negative,
                "true_negative": counts.true_negative,
                "false_positive": counts.false_positive,
                "precision": counts.precision,
                "recall": counts.recall,
                "f1": counts.f1,
                "false_positive_rate": counts.false_positive_rate,
            }

        return {
            "threshold": self.threshold,
            "overall": cell(self.overall),
            "by_subclass": {name: cell(c) for name, c in sorted(self.by_subclass.items())},
            "blind_subclasses": self.blind_subclasses(),
            "scores": dict(sorted(self.scores.items())),
            "unreadable": sorted(self.unreadable),
        }


def load_corpus(root: Path | str) -> List[Sample]:
    """Read every manifest entry into a Sample, in manifest order."""
    root = Path(root)
    manifest = root / "manifest.jsonl"
    if not manifest.is_file():
        raise CorpusError(f"no manifest.jsonl under {root}")

    samples: List[Sample] = []
    seen: set[str] = set()
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CorpusError(f"{manifest}:{number} is not JSON: {exc}") from exc
        missing = [f for f in REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            raise CorpusError(f"{manifest}:{number} missing {missing}")
        if entry["label"] not in LABELS:
            raise CorpusError(f"{manifest}:{number} unknown label {entry['label']!r}")
        if entry["id"] in seen:
            raise CorpusError(f"{manifest}:{number} duplicate id {entry['id']!r}")
        seen.add(entry["id"])

        path = root / entry["path"]
        if not path.is_file():
            raise CorpusError(f"{manifest}:{number} points at a missing file: {path}")
        samples.append(
            Sample(
                id=entry["id"],
                path=path,
                label=entry["label"],
                subclass=entry["subclass"],
                text=path.read_text(encoding="utf-8", errors="replace"),
            )
        )

    if not samples:
        raise CorpusError(f"{manifest} holds no entries")
    return samples


def evaluate(
    samples: Sequence[Sample],
    threshold: int,
    scorer: Callable[[str], int] | None = None,
) -> Evaluation:
    """Score every sample and tally the confusion matrix, overall and per subclass.

    ``scorer`` exists so a rebuilt detector can be measured against the same
    corpus without this module knowing anything about it. The default is the
    production path, which is what makes a run of this a statement about the
    product rather than about a fixture.
    """
    score_of = scorer or l1_scorer

    result = Evaluation(threshold=threshold, overall=Counts())
    for sample in samples:
        score = score_of(sample.text)
        result.scores[sample.id] = score
        flagged = score >= threshold
        bucket = result.by_subclass.setdefault(sample.subclass, Counts())
        for counts in (result.overall, bucket):
            if sample.is_injection and flagged:
                counts.true_positive += 1
            elif sample.is_injection:
                counts.false_negative += 1
            elif flagged:
                counts.false_positive += 1
            else:
                counts.true_negative += 1
    return result


def _rate(value: float | None) -> str:
    """A rate with no referent renders as a dash, never as a zero.

    The distinction the scorecard generator already makes for an unmeasured
    knob: a placeholder in a machine-readable table reads as a value the run
    chose. A benign-only slice has no precision, and 0.0% there would claim
    the detector fired and was always wrong.
    """
    return "--" if value is None else f"{value * 100:.1f}%"


def render_report(
    result: Evaluation,
    corpus: Path | str,
    counts: Dict[str, int],
    engine_version: str = __version__,
    generated_at: str | None = None,
    layers: str = "L1",
) -> str:
    """Turn an Evaluation into the committed Markdown artifact.

    Deterministic apart from the timestamp, so two runs of an unchanged
    detector produce a file that diffs to nothing. Every figure published
    about the detector comes from here; nothing is written by hand, the same
    rule the benchmark scorecards follow.
    """
    stamp = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    overall = result.overall

    lines = ["# Detector Evaluation", ""]
    lines.append(
        f"**recall {_rate(overall.recall)} — false positives {_rate(overall.false_positive_rate)}**"
    )
    lines.append("")
    lines.append("## Run metadata")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.append(f"| timestamp | {stamp} |")
    lines.append(f"| engine version | CyberAI {engine_version} |")
    lines.append(f"| corpus | {corpus} |")
    lines.append(f"| threshold | {result.threshold} |")
    lines.append(f"| layers | {layers} |")
    lines.append(f"| injections | {counts.get(INJECTION, 0)} |")
    lines.append(f"| benign | {counts.get(BENIGN, 0)} |")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("| --- | --- |")
    lines.append(f"| true positives | {overall.true_positive} |")
    lines.append(f"| false negatives | {overall.false_negative} |")
    lines.append(f"| false positives | {overall.false_positive} |")
    lines.append(f"| true negatives | {overall.true_negative} |")
    lines.append(f"| precision | {_rate(overall.precision)} |")
    lines.append(f"| recall | {_rate(overall.recall)} |")
    lines.append(f"| f1 | {_rate(overall.f1)} |")
    lines.append(f"| false positive rate | {_rate(overall.false_positive_rate)} |")
    lines.append("")
    lines.append("## Per-subclass breakdown")
    lines.append("")
    lines.append(
        "A slice holding no positives has no precision, and one holding no "
        "negatives has no false-positive rate. Those cells carry a dash. "
        "Percentages are only printed where the question has a subject."
    )
    lines.append("")
    lines.append("| subclass | n | flagged | precision | recall | FP rate |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for name, cell in sorted(result.by_subclass.items()):
        flagged = cell.true_positive + cell.false_positive
        precision = _rate(cell.precision) if cell.has_positives else "--"
        lines.append(
            f"| {name} | {cell.total} | {flagged} | {precision} | "
            f"{_rate(cell.recall)} | {_rate(cell.false_positive_rate)} |"
        )
    lines.append("")
    lines.append("## Blind subclasses")
    lines.append("")
    blind = result.blind_subclasses()
    if blind:
        lines.append(
            "Every sample in these scored below the threshold. This is what "
            "an overall recall figure cannot show, and it is the argument for "
            "a layer that is not a list of regular expressions."
        )
        lines.append("")
        for name in blind:
            cell = result.by_subclass[name]
            lines.append(f"- `{name}` — 0 of {cell.true_positive + cell.false_negative} flagged")
    else:
        lines.append("None: every injection subclass was flagged at least once.")
    lines.append("")
    return "\n".join(lines)


def label_counts(samples: Iterable[Sample]) -> Dict[str, int]:
    """How many samples carry each label. Used to report the corpus, not score it."""
    counts = {label: 0 for label in LABELS}
    for sample in samples:
        counts[sample.label] += 1
    return counts
