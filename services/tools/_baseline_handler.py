# services/tools/_baseline_handler.py
"""Handler for query_baseline_deviation tool — deterministic baseline queries."""

from typing import Any

from pydantic import BaseModel, Field

from services.tools.registry import ToolSpec


class QueryBaselineArgs(BaseModel):
    metric: str = Field(
        ...,
        description="Metric to query: 'cpu', 'ram', 'disk', or 'net_combo' (process:ip:port).",
    )
    current_value: float = Field(
        default=0.0,
        description="Current observed value (for deviation comparison). 0 = just query baseline.",
    )


def query_baseline_deviation_handler(metric: str, current_value: float = 0.0, **_) -> str:
    """Query baseline statistics (μ, σ) for a metric and compute Z-score deviation.

    Allows the agent to deterministically verify if current CPU/RAM/disk
    values deviate from the 7-day EMA baseline, instead of relying on
    memory of past incidents.
    """
    metric = metric.lower().strip()

    if metric == "net_combo":
        return "⚠️ net_combo baseline queries use is_known_combo() internally. Use get_external_connections instead."

    try:
        from services.ema_baseline import GatedEMABaseline

        ema = GatedEMABaseline()
        ema.load()
        mean, std = ema.get_stats(metric)
    except Exception as exc:
        return f"❌ Baseline query failed: {exc}"

    if mean is None or std is None:
        return f"📊 No baseline data for metric '{metric}'. System may not have enough history yet."

    lines = [
        f"📊 **Baseline Deviation: {metric.upper()}**",
        f"  Baseline μ = {mean:.1f}%",
        f"  Baseline σ = {std:.1f}%",
    ]

    if current_value > 0:
        z_score = (current_value - mean) / std if std > 0 else 0.0
        deviation = current_value - mean
        lines.append(f"  Current value = {current_value:.1f}%")
        lines.append(f"  Deviation = {deviation:+.1f}% (Z-score = {z_score:+.1f})")
        if abs(z_score) > 3.0:
            lines.append("  ⚠️ ANOMALY: Z-score > 3.0 — sustained deviation from baseline.")
        elif abs(z_score) > 2.0:
            lines.append("  ⚡ ELEVATED: Z-score > 2.0 — above normal range.")
        else:
            lines.append("  ✅ NORMAL: within baseline range.")
    else:
        lines.append("  (No current value provided — baseline only)")

    return "\n".join(lines)


def get_baseline_tool() -> ToolSpec:
    """Return the query_baseline_deviation ToolSpec."""
    return ToolSpec(
        name="query_baseline_deviation",
        description="Query system baseline (μ, σ) for cpu/ram/disk and compute Z-score deviation from current value. Deterministic — no LLM guessing.",
        pydantic_model=QueryBaselineArgs,
        handler=query_baseline_deviation_handler,
        safety_level="safe",
    )
