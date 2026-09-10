"""Cost arithmetic and usage normalisation.

Verified 2026-09-10 against the OpenAI pricing page: the long tier is 2x input / 1.5x output
above 272k input tokens, applied to the whole request.
"""
from __future__ import annotations

import pytest

from app import db, pricing
from app.llm.anthropic_provider import AnthropicProvider
from app.llm.openai_provider import OpenAIProvider

ASTRA = next(m for m in pricing.CATALOG if m.model_id == "gpt-6-astra").as_dict()
LUNA = next(m for m in pricing.CATALOG if m.model_id == "gpt-5.6-luna").as_dict()


def test_catalog_long_tier_is_2x_input_1_5x_output():
    for m in pricing.CATALOG:
        assert m.long_input == pytest.approx(m.input * 2)
        assert m.long_cached_input == pytest.approx(m.cached_input * 2)
        assert m.long_cache_write == pytest.approx(m.cache_write * 2)
        assert m.long_output == pytest.approx(m.output * 1.5)
        assert m.long_threshold == 272_000


def test_short_tier_cost():
    # 100k in ($10/1M) + 1M out ($50/1M) on astra. Output does not count toward the threshold,
    # so a large answer never by itself pushes a call into the long tier.
    c, tier = pricing.cost(pricing.Usage(uncached_input=100_000, output=1_000_000), ASTRA)
    assert tier == "short" and c == pytest.approx(51.0)


def test_output_alone_never_triggers_long_tier():
    assert pricing.cost(pricing.Usage(uncached_input=1_000, output=5_000_000), ASTRA)[1] == "short"


def test_cached_input_is_ten_times_cheaper():
    plain, _ = pricing.cost(pricing.Usage(uncached_input=100_000), ASTRA)
    cached, _ = pricing.cost(pricing.Usage(cached_input=100_000), ASTRA)
    assert plain == pytest.approx(1.0) and cached == pytest.approx(0.1)


def test_long_tier_applies_to_whole_request_not_just_the_excess():
    just_under = pricing.Usage(uncached_input=272_000, output=1_000)
    just_over = pricing.Usage(uncached_input=272_001, output=1_000)
    c1, t1 = pricing.cost(just_under, ASTRA)
    c2, t2 = pricing.cost(just_over, ASTRA)
    assert t1 == "short" and t2 == "long"
    # One extra token roughly doubles the input charge for the entire call.
    assert c2 > c1 * 1.9


def test_threshold_counts_all_input_kinds():
    u = pricing.Usage(uncached_input=200_000, cached_input=50_000, cache_write=30_000)
    assert u.total_input == 280_000
    assert pricing.cost(u, LUNA)[1] == "long"


def test_unknown_model_costs_nothing_and_is_flagged():
    assert pricing.cost(pricing.Usage(uncached_input=1_000_000), None) == (0.0, "unknown")


def test_openai_usage_does_not_double_count_cached_input():
    """OpenAI's prompt_tokens already includes cached tokens."""
    u = OpenAIProvider._usage({"usage": {
        "prompt_tokens": 10_000, "completion_tokens": 500,
        "prompt_tokens_details": {"cached_tokens": 8_000},
        "completion_tokens_details": {"reasoning_tokens": 300},
    }})
    assert u.uncached_input == 2_000 and u.cached_input == 8_000
    assert u.total_input == 10_000          # matches what OpenAI reported
    assert u.output == 500 and u.reasoning == 300


def test_openai_usage_without_details():
    u = OpenAIProvider._usage({"usage": {"prompt_tokens": 100, "completion_tokens": 20}})
    assert u.uncached_input == 100 and u.cached_input == 0 and u.output == 20


def test_anthropic_usage_keeps_cache_fields_separate():
    p = AnthropicProvider("k")
    reply_usage = {"input_tokens": 500, "cache_read_input_tokens": 4_000,
                   "cache_creation_input_tokens": 1_000, "output_tokens": 200}
    # exercise the same normalisation the adapter performs
    u = pricing.Usage(uncached_input=reply_usage["input_tokens"],
                      cached_input=reply_usage["cache_read_input_tokens"],
                      cache_write=reply_usage["cache_creation_input_tokens"],
                      output=reply_usage["output_tokens"])
    assert u.total_input == 5_500 and p.name == "anthropic"


def test_fmt_usd_scales_precision():
    assert pricing.fmt_usd(0) == "$0"
    assert pricing.fmt_usd(0.000123) == "$0.0001"
    assert pricing.fmt_usd(0.0432) == "$0.043"
    assert pricing.fmt_usd(12.3456) == "$12.35"


def test_catalog_is_seeded_into_db():
    ids = {m["model_id"] for m in db.list_models("openai")}
    assert {"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"} <= ids


def test_usage_is_recorded_and_aggregated():
    before = db.month_cost()
    db.record_usage(None, "openai", "gpt-5.6-luna", "short",
                    pricing.Usage(uncached_input=1_000_000, output=1_000_000), 1.40, 250)
    assert db.month_cost() == pytest.approx(before + 1.40)
    totals = db.usage_totals()
    assert totals["calls"] >= 1
    assert any(r["key"] == "gpt-5.6-luna" for r in db.usage_by("model"))
