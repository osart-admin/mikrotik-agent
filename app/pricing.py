"""Model catalogue and cost arithmetic.

Prices are per 1M tokens and are seeded into the DB on first run so they can be corrected from
the UI when a provider changes them - no rebuild needed. The built-in table below is only the
seed; `db.list_models()` is the source of truth at runtime.

Long-context billing: when a request's total input exceeds the model's threshold, the higher
tier applies to the *whole* request, not just the tokens above the line.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

# Verified 2026-09-10 against the OpenAI pricing page. The long tier is uniformly 2x input /
# 1.5x output above 272k input tokens, which cross-checks every row.
LONG_CONTEXT_THRESHOLD = 272_000


@dataclass
class ModelPrice:
    model_id: str
    provider: str
    label: str
    # per 1M tokens, short-context tier
    input: float
    cached_input: float
    cache_write: float
    output: float
    # per 1M tokens, long-context tier
    long_input: float
    long_cached_input: float
    long_cache_write: float
    long_output: float
    long_threshold: int = LONG_CONTEXT_THRESHOLD
    sort_order: int = 100

    def as_dict(self) -> dict:
        return asdict(self)


CATALOG: list[ModelPrice] = [
    ModelPrice("gpt-6-astra", "openai", "GPT-6 Astra — максимальное качество",
               10.00, 1.00, 12.50, 50.00, 20.00, 2.00, 25.00, 75.00, sort_order=10),
    ModelPrice("gpt-5.6-sol", "openai", "GPT-5.6 Sol — сильная модель",
               4.00, 0.40, 5.00, 20.00, 8.00, 0.80, 10.00, 30.00, sort_order=20),
    ModelPrice("gpt-5.6-terra", "openai", "GPT-5.6 Terra — баланс цены и качества",
               2.00, 0.20, 2.50, 12.00, 4.00, 0.40, 5.00, 18.00, sort_order=30),
    ModelPrice("gpt-5.6-luna", "openai", "GPT-5.6 Luna — самая дешёвая",
               0.20, 0.02, 0.25, 1.20, 0.40, 0.04, 0.50, 1.80, sort_order=40),
]

DEFAULT_MODEL = {"openai": "gpt-5.6-terra", "anthropic": ""}

# gpt-6-astra accepts low..max; older models accept low/medium/high or nothing at all. Empty
# means "do not send the parameter", which is the safe default for an unknown model.
REASONING_EFFORTS = ["", "low", "medium", "high", "xhigh", "max"]


@dataclass
class Usage:
    """Normalised token counts for one API call.

    ``uncached_input`` excludes cached and cache-write tokens so the three never double-count -
    providers disagree on whether their raw input figure already includes them.
    """
    uncached_input: int = 0
    cached_input: int = 0
    cache_write: int = 0
    output: int = 0
    reasoning: int = 0   # subset of output, tracked for display only - billed at the output rate

    @property
    def total_input(self) -> int:
        return self.uncached_input + self.cached_input + self.cache_write

    @property
    def total(self) -> int:
        return self.total_input + self.output


def cost(usage: Usage, price: dict | None) -> tuple[float, str]:
    """Return (cost in USD, tier) for one call. Unknown model -> 0.0 and tier 'unknown'."""
    if not price:
        return 0.0, "unknown"
    threshold = price.get("long_threshold") or LONG_CONTEXT_THRESHOLD
    long = usage.total_input > threshold
    tier = "long" if long else "short"
    p = (lambda k: float(price.get(("long_" + k) if long else k) or 0.0))
    total = (
        usage.uncached_input * p("input")
        + usage.cached_input * p("cached_input")
        + usage.cache_write * p("cache_write")
        + usage.output * p("output")
    ) / 1_000_000
    return round(total, 6), tier


def fmt_usd(amount: float | None) -> str:
    a = float(amount or 0.0)
    if a == 0:
        return "$0"
    if a < 0.01:
        return f"${a:.4f}"
    if a < 1:
        return f"${a:.3f}"
    return f"${a:,.2f}"
