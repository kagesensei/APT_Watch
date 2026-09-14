"""Small, dependency-free inline-SVG chart builders for the dashboard.

No external charting library — this stays a self-contained Flask app. Follows
the dataviz skill's mark specs: thin bars (<=24px), 4px rounded data-end
square at the baseline, a 2px surface gap between touching segments, labels
in text tokens (never the series color), a native <title> tooltip per mark,
and a legend for 2+ series. Every function returns a plain HTML/SVG string
built entirely from server-side data (never raw user input), rendered in the
template with `| safe` — the same trust level as any other server-rendered
fragment in this app.
"""

import html
from typing import Sequence

from contracts import precondition

BAR_HEIGHT = 18
ROW_GAP = 10
PADDING = 6
LABEL_WIDTH = 200
VALUE_GAP = 10
RADIUS = 4
SURFACE_GAP = 2  # dataviz skill: gap between touching stacked segments


def _esc(value: object) -> str:
    return html.escape(str(value))


def _truncate(label: object, max_len: int = 26) -> str:
    text = str(label)
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _round(n: float) -> float:
    return round(n, 1)


def _rounded_right_path(x: float, y: float, w: float, h: float, r: float) -> str:
    """Horizontal bar growing rightward from x: rounded right end, square
    (baseline) left end, per the dataviz skill's bar/column mark spec.
    """
    x, y, w, h = _round(x), _round(y), _round(w), _round(h)
    r = min(r, w / 2, h / 2) if w > 0 else 0
    if r <= 0:
        return f"M{x},{y} h{w} v{h} h{-w} Z"
    return (
        f"M{x},{y} "
        f"L{x + w - r},{y} "
        f"A{r},{r} 0 0 1 {x + w},{y + r} "
        f"L{x + w},{y + h - r} "
        f"A{r},{r} 0 0 1 {x + w - r},{y + h} "
        f"L{x},{y + h} Z"
    )


def _rounded_top_path(x: float, y: float, w: float, h: float, r: float) -> str:
    """Vertical column segment, rounded top (data-end), square bottom."""
    x, y, w, h = _round(x), _round(y), _round(w), _round(h)
    r = min(r, w / 2, h / 2) if h > 0 else 0
    if r <= 0:
        return f"M{x},{y} h{w} v{h} h{-w} Z"
    return (
        f"M{x},{y + r} "
        f"A{r},{r} 0 0 1 {x + r},{y} "
        f"L{x + w - r},{y} "
        f"A{r},{r} 0 0 1 {x + w},{y + r} "
        f"L{x + w},{y + h} "
        f"L{x},{y + h} Z"
    )


def _bar_chart_row(
    label: str, value: int, index: int, max_value: int, bar_area_width: float, color: str
) -> str:
    y = PADDING + index * (BAR_HEIGHT + ROW_GAP)
    bar_w = max(3.0, (value / max_value) * bar_area_width)
    text_y = y + BAR_HEIGHT * 0.72
    bar_x = LABEL_WIDTH
    path = _rounded_right_path(bar_x, y, bar_w, BAR_HEIGHT, RADIUS)
    return (
        f'<g><title>{_esc(label)}: {value:,}</title>'
        f'<text x="0" y="{text_y}" class="chart-label">{_esc(_truncate(label))}</text>'
        f'<path d="{path}" class="chart-bar" fill="{color}"></path>'
        f'<text x="{_round(bar_x + bar_w + VALUE_GAP)}" y="{text_y}" '
        f'class="chart-value">{value:,}</text>'
        f"</g>"
    )


def horizontal_bar_chart(
    items: Sequence[tuple[str, int]], color: str, width: int = 560
) -> str:
    """items: [(label, value), ...], already sorted descending.
    Returns an <svg> ranking chart: label at left (text token), thin
    rounded-end bar, value at the tip (text token, outside the fill) — a
    single sequential hue, so no legend needed (one series only).
    """
    if not items:
        return '<p class="empty">No data available.</p>'

    max_value = max(v for _, v in items) or 1
    bar_area_width = max(60, width - LABEL_WIDTH - 60)
    svg_height = PADDING * 2 + (BAR_HEIGHT + ROW_GAP) * len(items)

    rows = [
        _bar_chart_row(label, value, i, max_value, bar_area_width, color)
        for i, (label, value) in enumerate(items)
    ]

    return (
        f'<svg class="chart-svg" viewBox="0 0 {width} {svg_height}" '
        f'role="img" aria-label="Ranking bar chart">{"".join(rows)}</svg>'
    )


def _week_column_segments(
    x: float,
    week_index: int,
    week_label: str,
    series: Sequence[tuple[str, Sequence[int]]],
    colors: Sequence[str],
    max_total: int,
    baseline: float,
    col_width: float,
) -> str:
    y_cursor: float = baseline
    parts = []
    for series_index, (name, values) in enumerate(series):
        value = values[week_index]
        if value <= 0:
            continue
        seg_height = (value / max_total) * (baseline - PADDING)
        is_top = series_index == len(series) - 1 or all(
            v[1][week_index] == 0 for v in series[series_index + 1 :]
        )
        y_top = y_cursor - seg_height
        if is_top:
            path = _rounded_top_path(x, y_top, col_width, seg_height, RADIUS)
        else:
            path = (
                f"M{_round(x)},{_round(y_top)} h{_round(col_width)} "
                f"v{_round(seg_height)} h{_round(-col_width)} Z"
            )
        parts.append(
            f'<g><title>{_esc(name)}, week of {_esc(week_label)}: {value:,}</title>'
            f'<path d="{path}" fill="{colors[series_index]}"></path></g>'
        )
        y_cursor = y_top - SURFACE_GAP
    return "".join(parts)


def _week_axis_label(x: float, col_width: float, chart_height: int, week_label: str) -> str:
    return (
        f'<text x="{_round(x + col_width / 2)}" y="{chart_height - 6}" '
        f'class="chart-axis-label" text-anchor="middle">{_esc(week_label)}</text>'
    )


def _weekly_legend(series: Sequence[tuple[str, Sequence[int]]], colors: Sequence[str]) -> str:
    return "".join(
        f'<span class="chart-legend-item"><span class="chart-legend-swatch" '
        f'style="background:{colors[idx]}"></span>{_esc(name)}</span>'
        for idx, (name, _values) in enumerate(series)
    )


def stacked_weekly_chart(
    weeks: Sequence[str],
    series: Sequence[tuple[str, Sequence[int]]],
    colors: Sequence[str],
    width: int = 720,
    chart_height: int = 180,
) -> str:
    """weeks: [label, ...] (chronological). series: [(name, [values...]), ...],
    same length/order as weeks. colors: one hex per series, from the
    documented categorical palette (validated for this app's dark surface —
    see the plan/commit note), assigned in fixed order. Renders a legend
    (required for 2+ series) and a per-segment <title> tooltip.
    """
    if not weeks:
        return '<p class="empty">No data available.</p>'
    precondition(
        all(len(values) == len(weeks) for _name, values in series),
        "every series must have one value per week",
    )
    precondition(len(colors) >= len(series), "must have one color per series")

    totals = [sum(s[1][i] for s in series) for i in range(len(weeks))]
    max_total = max(totals) or 1

    col_gap = 6
    col_width = max(10.0, (width - PADDING * 2) / len(weeks) - col_gap)
    baseline = float(chart_height - 24)  # leave room for week labels below

    bars = []
    for i, week in enumerate(weeks):
        x = PADDING + i * (col_width + col_gap)
        bars.append(
            _week_column_segments(x, i, week, series, colors, max_total, baseline, col_width)
        )
        # sparse x-axis labels: first, last, and every ~4th to avoid crowding
        if i == 0 or i == len(weeks) - 1 or i % 4 == 0:
            bars.append(_week_axis_label(x, col_width, chart_height, week))

    svg = (
        f'<svg class="chart-svg" viewBox="0 0 {width} {chart_height}" '
        f'role="img" aria-label="Weekly stacked bar chart">{"".join(bars)}</svg>'
    )
    return f'<div class="chart-legend">{_weekly_legend(series, colors)}</div>{svg}'
