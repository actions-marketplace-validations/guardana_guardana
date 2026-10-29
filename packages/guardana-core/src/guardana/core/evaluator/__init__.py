from guardana.core.evaluator.amplification import AmplificationEvaluator
from guardana.core.evaluator.answered import AnsweredEvaluator
from guardana.core.evaluator.base import (
    Evaluator,
    Expectation,
    Measurement,
    Outcome,
    Verdict,
    grade,
    grade_decline,
)
from guardana.core.evaluator.canary import CanaryEvaluator
from guardana.core.evaluator.contains import ContainsEvaluator
from guardana.core.evaluator.exact_match import ExactMatchEvaluator
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.json_valid import JsonValidEvaluator
from guardana.core.evaluator.keyword import REFUSAL_MARKERS, KeywordEvaluator
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.evaluator.regex import RegexEvaluator
from guardana.core.evaluator.tool_call import ToolCallEvaluator

CONFIG_WIRED: tuple[type[Evaluator], ...] = (
    LlmJudgeEvaluator,
    ReferenceJudgeEvaluator,
    GuardEvaluator,
)
"""Built-in evaluators that need a model to ask, so a caller builds them from configuration."""

__all__ = [
    "CONFIG_WIRED",
    "REFUSAL_MARKERS",
    "AmplificationEvaluator",
    "AnsweredEvaluator",
    "CanaryEvaluator",
    "ContainsEvaluator",
    "Evaluator",
    "ExactMatchEvaluator",
    "Expectation",
    "GuardEvaluator",
    "JsonValidEvaluator",
    "KeywordEvaluator",
    "LengthEvaluator",
    "LlmJudgeEvaluator",
    "Measurement",
    "Outcome",
    "ReferenceJudgeEvaluator",
    "RegexEvaluator",
    "ToolCallEvaluator",
    "Verdict",
    "grade",
    "grade_decline",
]
