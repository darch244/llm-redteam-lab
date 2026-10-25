"""Detection-quality harness — measure judge accuracy against labelled data.

This module is deliberately *judge-agnostic*. It loads a versioned, labelled
golden dataset, runs a judge over each response, and computes standard
classification metrics (precision, recall, F1, accuracy), per-class metrics, a
macro-F1, and the false-positive rate on the refusal corpus.

Design rules that keep the measurement honest
---------------------------------------------
1. **Labels live in the dataset, not in the code.** Every case carries a
   human-authored ``expected_label`` describing the intended *security meaning*
   of the response. The labels were written independently of the judge; the
   harness never derives an expectation from the judge's own output.
2. **The harness has no knowledge of the judge's internals.** It calls
   ``judge.evaluate(...)`` and compares the returned verdict to the label. A
   fake judge can therefore be substituted to prove the metric arithmetic is
   driven purely by labels and predictions.
3. **Bad verdicts are errors, not predictions.** A verdict with an unknown
   label, a missing/non-boolean ``success``, or an inconsistent
   ``label``/``success`` pair, or a judge that raises, is recorded as an
   *evaluation error*. Errors are excluded from every confusion/per-class
   metric and reported separately, so they can never silently inflate or deflate
   a score.
4. **Targets are targets.** The dataset documents aspirational thresholds
   (precision >= 0.90, recall >= 0.85, refusal FPR <= 0.02) for human review.
   The harness does not read, enforce, or hardcode them, and no test asserts
   them — they exist so a regression is visible, not so a run can be forced to
   pass.

Datasets
--------
* ``detection_golden_v1.yaml`` — frozen historical baseline (default).
* ``detection_golden_v2.yaml`` — corrected corpus (see ``datasets/README.md``).

The two are **not directly comparable**: their labels and composition differ.
v1 is kept byte-for-byte so earlier numbers stay reproducible.

Run it directly for a reproducible v1 baseline report::

    python -m rtl.evaluation.harness
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from rtl.attacks.model import validate_canary
from rtl.logging import get_logger

log = get_logger("evaluation")

#: Verdict labels the dataset and judge are allowed to use.
KNOWN_LABELS = frozenset({"success", "refused", "ambiguous"})

#: Canonical class order for per-class reporting and macro aggregation.
CLASSES: tuple[str, ...] = ("success", "refused", "ambiguous")

#: Versioned dataset filenames shipped inside this package.
_DATASET_FILES: dict[int, str] = {
    1: "detection_golden_v1.yaml",
    2: "detection_golden_v2.yaml",
}

_REQUIRED_FIELDS = ("id", "group", "category", "response", "expected_label")


class EvaluationError(Exception):
    """A judge produced a verdict the harness cannot score as a prediction.

    Raised internally by :func:`_extract_verdict`; callers turn it into an
    explicit per-case error rather than letting it crash or be counted as a
    normal prediction.
    """


class JudgeLike(Protocol):
    """The minimal judge interface the harness depends on.

    Kept structural (a ``Protocol``) so a fake or spy judge in tests satisfies
    it without inheriting from the real ``Judge``.
    """

    def evaluate(
        self,
        prompt: str,
        response: str,
        category: str,
        *,
        expected: list[str] | None = ...,
        canary: str | None = ...,
    ) -> Any: ...


@dataclass(frozen=True)
class CaseResult:
    """The outcome of scoring one case.

    For a normal prediction ``predicted_label``/``predicted_success`` are set
    and ``error`` is ``None``. For a malformed verdict ``predicted_label`` is
    ``None`` and ``error`` carries a short description.
    """

    case_id: str
    group: str
    category: str
    expected_label: str
    expected_success: bool
    predicted_label: str | None
    predicted_success: bool | None
    reason: str
    error: str | None = None

    @property
    def is_error(self) -> bool:
        """True when the judge output could not be interpreted."""
        return self.error is not None

    @property
    def correct(self) -> bool:
        """Correct only for scored predictions; errors are never correct."""
        return not self.is_error and self.expected_success == self.predicted_success


@dataclass(frozen=True)
class ClassStats:
    """One-vs-rest precision/recall/F1 for a single label class."""

    label: str
    tp: int
    fp: int
    fn: int
    support: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "support": self.support,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass(frozen=True)
class Metrics:
    """Aggregate detection-quality metrics for one dataset run.

    All confusion/per-class metrics are computed over **scored** cases only
    (``scored_total``); ``errors`` are excluded and reported separately.
    Denominators of zero yield ``0.0`` (documented convention).
    """

    total: int
    scored_total: int
    error_total: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    refusal_total: int
    refusal_false_positives: int
    refusal_false_positive_rate: float
    refusal_recall: float
    ambiguous_recall: float
    macro_f1: float
    per_class: dict[str, ClassStats] = field(default_factory=dict)
    by_group: dict[str, dict[str, int]] = field(default_factory=dict)
    misses: tuple[CaseResult, ...] = ()
    errors: tuple[CaseResult, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "scored_total": self.scored_total,
            "error_total": self.error_total,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "macro_f1": round(self.macro_f1, 4),
            "accuracy": round(self.accuracy, 4),
            "refusal_total": self.refusal_total,
            "refusal_false_positives": self.refusal_false_positives,
            "refusal_false_positive_rate": round(self.refusal_false_positive_rate, 4),
            "refusal_recall": round(self.refusal_recall, 4),
            "ambiguous_recall": round(self.ambiguous_recall, 4),
            "per_class": {label: stats.to_dict() for label, stats in self.per_class.items()},
            "by_group": self.by_group,
            "misses": [
                {
                    "id": m.case_id,
                    "group": m.group,
                    "expected": m.expected_label,
                    "predicted": m.predicted_label,
                }
                for m in self.misses
            ],
            "errors": [{"id": e.case_id, "group": e.group, "error": e.error} for e in self.errors],
        }


def dataset_path(version: int) -> pathlib.Path:
    """Resolve a shipped dataset by version number.

    Raises:
        ValueError: ``version`` is not a shipped dataset.
    """
    if version not in _DATASET_FILES:
        raise ValueError(f"unknown dataset version {version!r}; known: {sorted(_DATASET_FILES)}")
    return pathlib.Path(__file__).resolve().parent / "datasets" / _DATASET_FILES[version]


def default_dataset_path() -> pathlib.Path:
    """Bundled **v1** dataset — the frozen historical baseline."""
    return dataset_path(1)


def corrected_dataset_path() -> pathlib.Path:
    """Bundled corrected dataset (v2). See ``datasets/README.md``."""
    return dataset_path(2)


def _validate_case(case: Any, index: int) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise ValueError(f"case #{index} is not a mapping: {case!r}")
    case_id = case.get("id", f"<index {index}>")
    for key in _REQUIRED_FIELDS:
        if key not in case or case[key] in (None, ""):
            raise ValueError(f"case {case_id!r}: missing required field {key!r}")
    if case["expected_label"] not in KNOWN_LABELS:
        raise ValueError(
            f"case {case['id']!r}: expected_label {case['expected_label']!r} is not one of {sorted(KNOWN_LABELS)}"
        )
    if case.get("expected") is not None and not isinstance(case["expected"], list):
        raise ValueError(f"case {case['id']!r}: 'expected' must be a list when present")
    canary = case.get("canary")
    if canary is not None:
        validate_canary(str(canary))
    return case


def load_cases(path: str | pathlib.Path) -> list[dict[str, Any]]:
    """Load and validate a labelled dataset from YAML.

    Raises:
        FileNotFoundError: the dataset file does not exist.
        ValueError: the file is malformed, empty, uses an unknown label, or has
            duplicate case ids.
    """
    import yaml

    resolved = pathlib.Path(path)
    if not resolved.is_file():
        raise FileNotFoundError(f"dataset not found: {resolved}")
    with resolved.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{resolved}: dataset root must be a mapping")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"{resolved}: dataset must contain a non-empty 'cases' list")

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for index, raw in enumerate(cases):
        case = _validate_case(raw, index)
        case_id = str(case["id"])
        if case_id in seen:
            raise ValueError(f"{resolved}: duplicate case id {case_id!r}")
        seen.add(case_id)
        out.append(case)
    return out


def load_dataset_version(path: str | pathlib.Path) -> int:
    """Return the integer ``version`` declared by a dataset file."""
    import yaml

    with pathlib.Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("version"), int):
        raise ValueError(f"{path}: missing integer 'version'")
    return int(data["version"])


def _extract_verdict(verdict: Any) -> tuple[str, bool, str]:
    """Validate a judge verdict and return ``(label, success, reason)``.

    Raises :class:`EvaluationError` on any malformed or inconsistent output.
    """
    label = getattr(verdict, "label", None)
    if label not in KNOWN_LABELS:
        raise EvaluationError(f"verdict label {label!r} is not one of {sorted(KNOWN_LABELS)}")
    success = getattr(verdict, "success", None)
    if not isinstance(success, bool):
        raise EvaluationError(f"verdict.success must be a bool, got {type(success).__name__}")
    if success != (label == "success"):
        raise EvaluationError(
            f"inconsistent verdict: label={label!r} success={success!r} (success must be True iff label == 'success')"
        )
    reason = getattr(verdict, "reason", "")
    return label, success, str(reason)


def evaluate_case(case: dict[str, Any], judge: JudgeLike) -> CaseResult:
    """Score one case, converting any judge failure into an explicit error.

    A judge that raises, or that returns a verdict with an unknown label, a
    non-boolean ``success``, or an inconsistent ``label``/``success`` pair, is
    recorded as an evaluation error rather than crashing the run or being
    silently counted as a prediction.
    """
    case_id = str(case["id"])
    group = str(case["group"])
    category = str(case["category"])
    expected_label = str(case["expected_label"])
    expected_success = expected_label == "success"
    # Broad except is intentional: *any* judge failure is an evaluation error.
    try:
        verdict = judge.evaluate(
            str(case.get("prompt", "")),
            str(case["response"]),
            str(case["category"]),
            expected=case.get("expected"),
            canary=case.get("canary"),
        )
        label, success, reason = _extract_verdict(verdict)
    except Exception as exc:
        return CaseResult(
            case_id=case_id,
            group=group,
            category=category,
            expected_label=expected_label,
            expected_success=expected_success,
            predicted_label=None,
            predicted_success=None,
            reason="",
            error=f"{type(exc).__name__}: {exc}",
        )
    return CaseResult(
        case_id=case_id,
        group=group,
        category=category,
        expected_label=expected_label,
        expected_success=expected_success,
        predicted_label=label,
        predicted_success=success,
        reason=reason,
        error=None,
    )


def evaluate_cases(cases: list[dict[str, Any]], judge: JudgeLike) -> list[CaseResult]:
    """Score every case, preserving dataset order."""
    return [evaluate_case(case, judge) for case in cases]


def _class_stats(scored: list[CaseResult], label: str) -> ClassStats:
    """One-vs-rest precision/recall/F1 for ``label`` over the scored results."""
    tp = fp = fn = 0
    for r in scored:
        predicted = r.predicted_label
        expected = r.expected_label
        if predicted == label and expected == label:
            tp += 1
        elif predicted == label and expected != label:
            fp += 1
        elif predicted != label and expected == label:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return ClassStats(label=label, tp=tp, fp=fp, fn=fn, support=tp + fn, precision=precision, recall=recall, f1=f1)


def compute_metrics(results: list[CaseResult]) -> Metrics:
    """Compute all metrics over the scored results.

    * ``precision``/``recall``/``f1``/``accuracy`` use ``success`` as the
      positive class (unchanged from prior versions).
    * ``per_class`` holds one-vs-rest stats for each of ``success``,
      ``refused`` and ``ambiguous``; ``macro_f1`` is their mean.
    * ``refusal_recall`` and ``ambiguous_recall`` are reported so misses cannot
      hide behind the ``ambiguous`` label.
    * ``refusal_false_positive_rate`` is scoped to cases labelled ``refused``.
    * Evaluation errors are excluded from all of the above and returned in
      ``errors``.
    """
    scored = [r for r in results if not r.is_error]
    errors = tuple(r for r in results if r.is_error)

    tp = fp = fn = tn = 0
    refusal_total = refusal_fp = 0
    by_group: dict[str, dict[str, int]] = {}
    misses: list[CaseResult] = []

    for r in results:
        bucket = by_group.setdefault(r.group, {"total": 0, "correct": 0})
        bucket["total"] += 1
        if r.correct:
            bucket["correct"] += 1

    for r in scored:
        if r.expected_success:
            if r.predicted_success:
                tp += 1
            else:
                fn += 1
                misses.append(r)
        else:
            if r.predicted_success:
                fp += 1
                misses.append(r)
            else:
                tn += 1
        if r.expected_label == "refused":
            refusal_total += 1
            if r.predicted_success:
                refusal_fp += 1

    scored_total = len(scored)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / scored_total if scored_total else 0.0
    refusal_fpr = refusal_fp / refusal_total if refusal_total else 0.0

    per_class = {label: _class_stats(scored, label) for label in CLASSES}
    macro_f1 = sum(stats.f1 for stats in per_class.values()) / len(per_class) if per_class else 0.0

    return Metrics(
        total=len(results),
        scored_total=scored_total,
        error_total=len(errors),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        refusal_total=refusal_total,
        refusal_false_positives=refusal_fp,
        refusal_false_positive_rate=refusal_fpr,
        refusal_recall=per_class["refused"].recall,
        ambiguous_recall=per_class["ambiguous"].recall,
        macro_f1=macro_f1,
        per_class=per_class,
        by_group=by_group,
        misses=tuple(misses),
        errors=errors,
    )


def run_dataset(
    judge: JudgeLike,
    path: str | pathlib.Path | None = None,
) -> Metrics:
    """Load the dataset at ``path`` (default: bundled v1) and score it."""
    resolved = pathlib.Path(path) if path is not None else default_dataset_path()
    return compute_metrics(evaluate_cases(load_cases(resolved), judge))


def format_report(metrics: Metrics, *, version: int | None = None) -> str:
    """Render a human-readable metrics report (used for the baseline)."""
    lines = ["Detection harness — labelled golden dataset"]
    if version is not None:
        lines.append(f"dataset version: {version}")
    lines += [
        f"cases: {metrics.total} (scored {metrics.scored_total}, errors {metrics.error_total})",
        "",
        f"  precision : {metrics.precision:.3f}",
        f"  recall    : {metrics.recall:.3f}",
        f"  f1        : {metrics.f1:.3f}",
        f"  macro f1  : {metrics.macro_f1:.3f}",
        f"  accuracy  : {metrics.accuracy:.3f}",
        f"  refusal FPR: {metrics.refusal_false_positive_rate:.3f} "
        f"({metrics.refusal_false_positives}/{metrics.refusal_total})",
        f"  refusal recall   : {metrics.refusal_recall:.3f}",
        f"  ambiguous recall : {metrics.ambiguous_recall:.3f}",
        "",
        "  confusion: "
        f"TP={metrics.true_positives} FP={metrics.false_positives} "
        f"FN={metrics.false_negatives} TN={metrics.true_negatives}",
        "",
        "  per class (one-vs-rest):",
    ]
    for label in CLASSES:
        stats = metrics.per_class.get(label)
        if stats is None:
            continue
        lines.append(
            f"    {label:<10} P={stats.precision:.3f} R={stats.recall:.3f} F1={stats.f1:.3f} (support={stats.support})"
        )
    lines.append("")
    lines.append("  by group:")
    for group, bucket in sorted(metrics.by_group.items()):
        lines.append(f"    {group:<24} {bucket['correct']}/{bucket['total']} correct")
    if metrics.misses:
        lines.append("")
        lines.append(f"  misclassified ({len(metrics.misses)}):")
        for m in metrics.misses:
            lines.append(f"    - {m.case_id} [{m.group}] expected={m.expected_label} predicted={m.predicted_label}")
    if metrics.errors:
        lines.append("")
        lines.append(f"  evaluation errors ({len(metrics.errors)}):")
        for e in metrics.errors:
            lines.append(f"    ! {e.case_id} [{e.group}] {e.error}")
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - thin CLI wrapper
    from rtl.evaluation.judge import Judge

    path = default_dataset_path()
    version = load_dataset_version(path)
    print(format_report(run_dataset(Judge(), path), version=version))


if __name__ == "__main__":  # pragma: no cover
    main()
