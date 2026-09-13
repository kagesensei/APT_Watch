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

BAR_HEIGHT = 18
ROW_GAP = 10
PADDING = 6
LABEL_WIDTH = 200
VALUE_GAP = 10
RADIUS = 4
SURFACE_GAP = 2  # dataviz skill: gap between touching stacked segments


def _esc(value):
    return html.escape(str(value))


def _truncate(label, max_len=26):
    label = str(label)
    return label if len(label) <= max_len else label[: max_len - 1] + "…"


def _round(n):
    return round(n, 1)


def _rounded_right_path(x, y, w, h, r):
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


def _rounded_top_path(x, y, w, h, r):
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


def horizontal_bar_chart(items, color, width=560):
    """items: [(label, value), ...], already sorted descending.
    Returns an <svg> ranking chart: label at left (text token), thin
    rounded-end bar, value at the tip (text token, outside the fill) — a
    single sequential hue, so no legend needed (one series only).
    """
    if not items:
        return '<p class="empty">No data available.</p>'

    max_value = max(v for _, v in items) or 1
    bar_area_width = max(60, width - LABEL_WIDTH - 60)
    row_height = BAR_HEIGHT + ROW_GAP
    svg_height = PADDING * 2 + row_height * len(items)

    rows = []
    for i, (label, value) in enumerate(items):
        y = PADDING + i * row_height
        bar_w = max(3, (value / max_value) * bar_area_width)
        text_y = y + BAR_HEIGHT * 0.72
        bar_x = LABEL_WIDTH
        path = _rounded_right_path(bar_x, y, bar_w, BAR_HEIGHT, RADIUS)
        rows.append(
            f'<g><title>{_esc(label)}: {value:,}</title>'
            f'<text x="0" y="{text_y}" class="chart-label">{_esc(_truncate(label))}</text>'
            f'<path d="{path}" class="chart-bar" fill="{color}"></path>'
            f'<text x="{_round(bar_x + bar_w + VALUE_GAP)}" y="{text_y}" class="chart-value">{value:,}</text>'
            f"</g>"
        )

    return (
        f'<svg class="chart-svg" viewBox="0 0 {width} {svg_height}" '
        f'role="img" aria-label="Ranking bar chart">{"".join(rows)}</svg>'
    )


def stacked_weekly_chart(weeks, series, colors, width=720, chart_height=180):
    """weeks: [label, ...] (chronological). series: [(name, [values...]), ...],
    same length/order as weeks. colors: one hex per series, from the
    documented categorical palette (validated for this app's dark surface —
    see the plan/commit note), assigned in fixed order. Renders a legend
    (required for 2+ series) and a per-segment <title> tooltip.
    """
    if not weeks:
        return '<p class="empty">No data available.</p>'

    totals = [sum(s[1][i] for s in series) for i in range(len(weeks))]
    max_total = max(totals) or 1

    col_gap = 6
    col_width = max(10, (width - PADDING * 2) / len(weeks) - col_gap)
    baseline = chart_height - 24  # leave room for week labels below

    bars = []
    for i, week in enumerate(weeks):
        x = PADDING + i * (col_width + col_gap)
        y_cursor = baseline
        for series_index, (name, values) in enumerate(series):
            value = values[i]
            if value <= 0:
                continue
            seg_height = (value / max_total) * (baseline - PADDING)
            is_top = series_index == len(series) - 1 or all(
                v[1][i] == 0 for v in series[series_index + 1 :]
            )
            y_top = y_cursor - seg_height
            if is_top:
                path = _rounded_top_path(x, y_top, col_width, seg_height, RADIUS)
            else:
                path = (
                    f"M{_round(x)},{_round(y_top)} h{_round(col_width)} "
                    f"v{_round(seg_height)} h{_round(-col_width)} Z"
                )
            bars.append(
                f'<g><title>{_esc(name)}, week of {_esc(week)}: {value:,}</title>'
                f'<path d="{path}" fill="{colors[series_index]}"></path></g>'
            )
            y_cursor = y_top - SURFACE_GAP
        # sparse x-axis labels: first, last, and every ~4th to avoid crowding
        if i == 0 or i == len(weeks) - 1 or i % 4 == 0:
            bars.append(
                f'<text x="{_round(x + col_width / 2)}" y="{chart_height - 6}" '
                f'class="chart-axis-label" text-anchor="middle">{_esc(week)}</text>'
            )

    legend = "".join(
        f'<span class="chart-legend-item"><span class="chart-legend-swatch" '
        f'style="background:{colors[idx]}"></span>{_esc(name)}</span>'
        for idx, (name, _values) in enumerate(series)
    )

    svg = (
        f'<svg class="chart-svg" viewBox="0 0 {width} {chart_height}" '
        f'role="img" aria-label="Weekly stacked bar chart">{"".join(bars)}</svg>'
    )
    return f'<div class="chart-legend">{legend}</div>{svg}'
