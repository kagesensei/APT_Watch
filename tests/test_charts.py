from app import charts


class TestHorizontalBarChart:
    def test_empty_items_renders_fallback_message(self):
        assert charts.horizontal_bar_chart([], "#4fd1c5") == '<p class="empty">No data available.</p>'

    def test_renders_one_group_per_item_with_svg_wrapper(self):
        svg = charts.horizontal_bar_chart([("APT29", 42), ("APT28", 10)], "#4fd1c5")
        assert svg.startswith("<svg")
        assert svg.count("<g>") == 2
        assert "42" in svg and "10" in svg

    def test_label_and_value_text_are_html_escaped(self):
        svg = charts.horizontal_bar_chart([("<script>alert(1)</script>", 5)], "#4fd1c5")
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg

    def test_long_labels_are_truncated_in_the_visible_text_but_kept_in_full_in_the_tooltip(self):
        long_label = "A" * 50
        svg = charts.horizontal_bar_chart([(long_label, 1)], "#4fd1c5")
        assert f"<title>{long_label}: 1</title>" in svg  # full label preserved for the tooltip
        assert '<text x="0"' in svg and "…" in svg  # visible label is truncated with an ellipsis
        assert f'>{long_label}<' not in svg  # but never rendered in full as visible text

    def test_zero_value_item_still_renders_a_minimum_width_bar(self):
        svg = charts.horizontal_bar_chart([("Zero", 0)], "#4fd1c5")
        assert "Zero" in svg
        # max(3, ...) floor keeps a visible sliver instead of a zero-width bar
        assert 'class="chart-bar"' in svg

    def test_values_use_thousands_separators(self):
        svg = charts.horizontal_bar_chart([("Big", 12345)], "#4fd1c5")
        assert "12,345" in svg


class TestStackedWeeklyChart:
    def test_empty_weeks_renders_fallback_message(self):
        assert charts.stacked_weekly_chart([], [], []) == '<p class="empty">No data available.</p>'

    def test_renders_legend_entry_per_series(self):
        html_out = charts.stacked_weekly_chart(
            ["Jan 01", "Jan 08"],
            [("Ransomware-linked", [3, 1]), ("Other", [2, 4])],
            ["#3987e5", "#d95926"],
        )
        assert html_out.count("chart-legend-item") == 2
        assert "Ransomware-linked" in html_out
        assert "Other" in html_out

    def test_segments_with_zero_value_are_skipped(self):
        html_out = charts.stacked_weekly_chart(
            ["Jan 01"], [("A", [0]), ("B", [5])], ["#111111", "#222222"]
        )
        # Only one <path> segment should be drawn (A's zero-value week is skipped).
        assert html_out.count("<path") == 1

    def test_series_and_week_names_are_html_escaped(self):
        html_out = charts.stacked_weekly_chart(
            ["<b>Jan 01</b>"], [("<script>x</script>", [1])], ["#111111"]
        )
        assert "<script>x</script>" not in html_out
        assert "&lt;script&gt;" in html_out

    def test_axis_labels_are_sparse_first_last_and_every_fourth(self):
        weeks = [f"W{i}" for i in range(10)]
        series = [("Only", [1] * 10)]
        html_out = charts.stacked_weekly_chart(weeks, series, ["#111111"])
        for i in (0, 4, 8, 9):
            assert f">{weeks[i]}<" in html_out
        for i in (1, 2, 3, 5, 6, 7):
            assert f">{weeks[i]}<" not in html_out
