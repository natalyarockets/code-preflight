"""Render scan results as a professionally styled PDF report.

Uses fpdf2 drawing primitives (no markdown-to-HTML conversion).
Install via: pip install la-analyzer[pdf]
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from la_analyzer.render._helpers import (
    count_py_files,
    executive_summary,
    latin1,
    leak_label,
    sev_order,
    strip_bandit_prefix,
    top_risks,
)
from la_analyzer.scanner import ScanResult


# ── Color palette ──────────────────────────────────────────────────────────

_SEV_COLORS: dict[str, tuple[tuple[int, int, int], tuple[int, int, int]]] = {
    # severity -> (text_rgb, bg_rgb)
    "critical": ((185, 28, 28), (254, 226, 226)),
    "high":     ((194, 80, 0), (255, 237, 213)),
    "medium":   ((161, 120, 0), (254, 249, 195)),
    "low":      ((75, 85, 99), (229, 231, 235)),
    "info":     ((75, 85, 99), (229, 231, 235)),
}

_GATE_COLORS = {
    "blocked": ((185, 28, 28), (254, 226, 226)),
    "review":  ((194, 80, 0), (255, 237, 213)),
    "pass":    ((22, 101, 52), (220, 252, 231)),
}

_CHARCOAL = (31, 41, 55)
_WHITE = (255, 255, 255)
_ALT_ROW = (248, 249, 250)
_BODY = (30, 30, 30)
_MUTED = (100, 100, 100)
_DIVIDER = (200, 200, 200)

# Column widths for standard tables
_MATRIX_COLS = (40, 16, 14, 14, 16, 14, 14, 14, 14, 14)  # total = 170 < 180
_PROMPT_COLS = (35, 22, 50, 35, 28)               # total = 170 < 180
_TOOL_COLS = (30, 22, 40, 40, 38)                  # total = 170 < 180
_STATE_COLS = (35, 50, 50, 35)                     # total = 170 < 180
_TOOLCHAIN_COLS = (35, 20, 22, 18, 75)              # total = 170 < 180
_EFFECT_COLS = (30, 55, 22, 63)                      # total = 170 < 180


def render_pdf(result: ScanResult, output_path: Path) -> None:
    """Render the scan result to a professionally styled PDF file."""
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        raise ImportError(
            "PDF output requires 'fpdf2'. "
            "Install it with: pip install la-analyzer[pdf]"
        )

    pdf = _SecurityReportPDF(result, FPDF, XPos, YPos)
    pdf.render()
    pdf.output(str(output_path))


class _SecurityReportPDF:
    """Builds a multi-page PDF from a ScanResult using fpdf2 drawing primitives."""

    def __init__(self, result: ScanResult, fpdf_cls, xpos_enum, ypos_enum):
        self._result = result
        self._XPos = xpos_enum
        self._YPos = ypos_enum
        self._name = result.project_path.name
        self._date = date.today().isoformat()

        self._pdf = fpdf_cls()
        self._pdf.set_auto_page_break(auto=True, margin=20)
        self._pdf.set_margins(15, 20, 15)
        self._content_w = 180  # 210 - 15 - 15

        # Track whether we're past the title page for header rendering
        self._past_title = False

    # ── Delegation ─────────────────────────────────────────────────────

    def output(self, path: str) -> None:
        self._pdf.output(path)

    # ── Header / Footer ───────────────────────────────────────────────

    def _add_page(self) -> None:
        """Add a page; mark past-title after the first."""
        self._pdf.add_page()
        page = self._pdf.page_no()
        if page > 1:
            self._past_title = True
            # Header on pages 2+
            self._pdf.set_font("Helvetica", "B", 8)
            self._pdf.set_text_color(*_MUTED)
            self._pdf.set_y(10)
            self._pdf.cell(self._content_w / 2, 5, self._safe(f"{self._name} -- Security Report"), new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            self._pdf.set_font("Helvetica", "", 8)
            self._pdf.cell(self._content_w / 2, 5, self._date, align="R", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            # Thin gray line
            self._pdf.set_draw_color(*_DIVIDER)
            self._pdf.line(15, 16, 195, 16)
            self._pdf.set_y(20)

    def _footer(self) -> None:
        """Draw footer on current page (called before adding next page).

        Must disable auto_page_break to avoid fpdf2 inserting a blank page
        when we draw below the break threshold (y=283 > margin at 277).
        """
        self._pdf.set_auto_page_break(auto=False)
        self._pdf.set_draw_color(*_DIVIDER)
        self._pdf.line(15, 282, 195, 282)
        self._pdf.set_y(283)
        self._pdf.set_font("Helvetica", "", 7.5)
        self._pdf.set_text_color(*_MUTED)
        self._pdf.cell(self._content_w, 5, f"Page {self._pdf.page_no()}", align="R")
        self._pdf.set_auto_page_break(auto=True, margin=20)

    # ── Drawing helpers ────────────────────────────────────────────────

    def _safe(self, text: str) -> str:
        return latin1(str(text))

    def _set_body_text(self) -> None:
        self._pdf.set_font("Helvetica", "", 9)
        self._pdf.set_text_color(*_BODY)

    def _divider(self) -> None:
        y = self._pdf.get_y() + 2
        self._pdf.set_draw_color(*_DIVIDER)
        self._pdf.line(15, y, 195, y)
        self._pdf.set_y(y + 4)

    def _heading(self, text: str, level: int = 2) -> None:
        sizes = {2: 14, 3: 11, 4: 9.5}
        sz = sizes.get(level, 11)
        spacing = {2: 8, 3: 5, 4: 3}
        self._ensure_space(sz + spacing.get(level, 5) + 5)
        self._pdf.ln(spacing.get(level, 5))
        self._pdf.set_font("Helvetica", "B", sz)
        self._pdf.set_text_color(*_BODY)
        self._pdf.cell(self._content_w, sz * 0.5, self._safe(text), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.ln(2)

    def _severity_badge(self, sev: str) -> None:
        """Draw a colored rounded-rect pill with severity text."""
        text_c, bg_c = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
        label = sev.upper()
        self._pdf.set_font("Helvetica", "B", 7)
        w = self._pdf.get_string_width(label) + 4
        h = 4.5
        x = self._pdf.get_x()
        y = self._pdf.get_y()
        # Background pill
        self._pdf.set_fill_color(*bg_c)
        self._pdf.set_draw_color(*bg_c)
        self._pdf.rect(x, y, w, h, style="FD")
        # Text
        self._pdf.set_text_color(*text_c)
        self._pdf.set_xy(x, y)
        self._pdf.cell(w, h, label, align="C", new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
        self._pdf.set_x(x + w + 2)

    def _bullet(self, text: str, indent: float = 4) -> None:
        self._set_body_text()
        x0 = self._pdf.get_x()
        self._pdf.set_x(x0 + indent)
        # Filled circle
        cy = self._pdf.get_y() + 1.5
        self._pdf.set_fill_color(*_BODY)
        self._pdf.ellipse(self._pdf.get_x(), cy, 1.2, 1.2, style="F")
        self._pdf.set_x(self._pdf.get_x() + 3)
        # Wrapped text
        self._pdf.multi_cell(self._content_w - indent - 7, 4, self._safe(text), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

    def _kv(self, key: str, value: str) -> None:
        self._pdf.set_font("Helvetica", "B", 9)
        self._pdf.set_text_color(*_BODY)
        kw = self._pdf.get_string_width(key + ": ") + 2
        self._pdf.cell(kw, 4.5, self._safe(key + ":"), new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
        self._pdf.set_font("Helvetica", "", 9)
        self._pdf.multi_cell(self._content_w - kw, 4.5, self._safe(value), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

    def _ensure_space(self, needed: float = 20) -> None:
        """Add a new page if less than `needed` mm remain."""
        if self._pdf.get_y() + needed > 275:
            self._footer()
            self._add_page()

    def _table_header(self, cols: tuple[float, ...], headers: list[str]) -> None:
        """Draw a charcoal header row."""
        self._ensure_space(12)
        self._pdf.set_fill_color(*_CHARCOAL)
        self._pdf.set_text_color(*_WHITE)
        self._pdf.set_font("Helvetica", "B", 7.5)
        for i, hdr in enumerate(headers):
            last = i == len(headers) - 1
            self._pdf.cell(
                cols[i], 6, self._safe(hdr), border=0, fill=True,
                align="L",
                new_x=self._XPos.LMARGIN if last else self._XPos.RIGHT,
                new_y=self._YPos.NEXT if last else self._YPos.TOP,
            )

    def _table_row(self, cols: tuple[float, ...], values: list[str], row_idx: int) -> None:
        """Draw a data row, alternating background."""
        self._ensure_space(8)
        if row_idx % 2 == 1:
            self._pdf.set_fill_color(*_ALT_ROW)
            fill = True
        else:
            fill = False
        self._pdf.set_text_color(*_BODY)
        self._pdf.set_font("Helvetica", "", 7.5)
        for i, val in enumerate(values):
            last = i == len(values) - 1
            self._pdf.cell(
                cols[i], 5.5, self._safe(val), border=0, fill=fill,
                align="L",
                new_x=self._XPos.LMARGIN if last else self._XPos.RIGHT,
                new_y=self._YPos.NEXT if last else self._YPos.TOP,
            )

    def _table_row_with_badge(self, cols: tuple[float, ...], values: list[str],
                               row_idx: int, badge_col: int, badge_sev: str) -> None:
        """Draw a data row where one column is a severity badge instead of plain text."""
        self._ensure_space(8)
        if row_idx % 2 == 1:
            self._pdf.set_fill_color(*_ALT_ROW)
            fill = True
        else:
            fill = False
        self._pdf.set_text_color(*_BODY)
        self._pdf.set_font("Helvetica", "", 7.5)
        y_start = self._pdf.get_y()
        for i, val in enumerate(values):
            last = i == len(values) - 1
            if i == badge_col:
                # Draw background fill for the cell area
                if fill:
                    x_here = self._pdf.get_x()
                    self._pdf.set_fill_color(*_ALT_ROW)
                    self._pdf.rect(x_here, y_start, cols[i], 5.5, style="F")
                self._severity_badge(badge_sev)
                # Advance to next column position
                if not last:
                    self._pdf.set_xy(15 + sum(cols[:i + 1]), y_start)
                else:
                    self._pdf.set_xy(15, y_start + 5.5)
            else:
                self._pdf.cell(
                    cols[i], 5.5, self._safe(val), border=0, fill=fill,
                    align="L",
                    new_x=self._XPos.LMARGIN if last else self._XPos.RIGHT,
                    new_y=self._YPos.NEXT if last else self._YPos.TOP,
                )

    # ── Main render ────────────────────────────────────────────────────

    def render(self) -> None:
        self._add_page()
        self._render_title()
        self._render_executive_summary()
        self._render_summary_card()
        self._render_trust_boundaries()
        self._render_structural_summary()
        self._render_prompt_surfaces()
        self._render_tool_registrations()
        self._render_state_flow()
        self._render_entrypoint_matrix()
        self._render_security_findings()
        self._render_call_graph()
        self._render_toolchain_appendix()
        # Footer on last page
        self._footer()

    # ── 1. Title block ─────────────────────────────────────────────────

    def _render_title(self) -> None:
        self._pdf.ln(15)
        self._pdf.set_font("Helvetica", "B", 20)
        self._pdf.set_text_color(*_BODY)
        self._pdf.cell(self._content_w, 10, self._safe(self._name), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.set_font("Helvetica", "", 10)
        self._pdf.set_text_color(*_MUTED)
        self._pdf.cell(self._content_w, 6, "Static Runtime Projection and Safety Audit", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.cell(self._content_w, 6, self._date, new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.ln(6)
        self._divider()

    # ── 1b. Executive summary ──────────────────────────────────────────

    def _render_executive_summary(self) -> None:
        bullets = executive_summary(self._result)
        if not bullets:
            return

        self._heading("If You Deploy This As-Is")

        for b in bullets:
            self._bullet(b)

        self._pdf.ln(2)
        self._divider()

    # ── 2. Summary card ────────────────────────────────────────────────

    def _render_summary_card(self) -> None:
        s = self._result.security
        self._heading("Security Summary")

        if not s:
            self._set_body_text()
            self._pdf.set_text_color(*_MUTED)
            self._pdf.multi_cell(self._content_w, 5, "Security scan was not run. Use la-scan without --no-security for full results.", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            self._pdf.ln(4)
            return

        # Gate decision -- colored background card (wording comes from the model)
        gate = s.gate_status
        gate_label = s.gate_message

        text_c, bg_c = _GATE_COLORS[gate]

        # Card background
        card_y = self._pdf.get_y()
        card_x = 15

        # Pre-calculate card height: gate label + severity row + risks
        risks = top_risks(self._result)
        # Use 7pt per risk (vs content width) to budget for potential line-wrapping.
        card_h = 8 + 10 + (len(risks) * 7 if risks else 0) + 6

        self._ensure_space(card_h + 5)
        card_y = self._pdf.get_y()

        self._pdf.set_fill_color(*bg_c)
        self._pdf.rect(card_x, card_y, self._content_w, card_h, style="F")

        # Gate label
        self._pdf.set_xy(card_x + 4, card_y + 3)
        self._pdf.set_font("Helvetica", "B", 10)
        self._pdf.set_text_color(*text_c)
        self._pdf.cell(self._content_w - 8, 6, self._safe(gate_label), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

        # Severity count boxes
        self._pdf.set_xy(card_x + 4, card_y + 11)
        sev_labels = [
            ("Critical", s.critical_count, "critical"),
            ("High", s.high_count, "high"),
            ("Medium", s.medium_count, "medium"),
            ("Low", s.low_count, "low"),
        ]
        for label, count, sev in sev_labels:
            tc, bc = _SEV_COLORS[sev]
            x = self._pdf.get_x()
            y = self._pdf.get_y()
            box_w = 30
            self._pdf.set_fill_color(*bc)
            self._pdf.rect(x, y, box_w, 7, style="F")
            self._pdf.set_font("Helvetica", "B", 8)
            self._pdf.set_text_color(*tc)
            self._pdf.set_xy(x, y)
            self._pdf.cell(box_w, 3.5, label, align="C", new_x=self._XPos.LEFT, new_y=self._YPos.NEXT)
            self._pdf.set_font("Helvetica", "B", 10)
            self._pdf.cell(box_w, 3.5, str(count), align="C", new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            self._pdf.set_xy(x + box_w + 4, y)

        # Top risks
        if risks:
            self._pdf.set_xy(card_x + 4, card_y + 20)
            self._pdf.set_font("Helvetica", "B", 8)
            self._pdf.set_text_color(*text_c)
            self._pdf.cell(
                self._content_w - 8,
                4,
                self._safe(f"High / critical findings ({len(risks)}):"),
                new_x=self._XPos.LMARGIN,
                new_y=self._YPos.NEXT,
            )
            self._pdf.set_font("Helvetica", "", 8)
            for risk in risks:
                self._pdf.set_x(card_x + 6)
                self._pdf.cell(2, 4, "-", new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
                self._pdf.multi_cell(self._content_w - 14, 4, self._safe(risk), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

        self._pdf.set_y(card_y + card_h + 4)

    # ── 3. Trust boundaries ────────────────────────────────────────────

    def _render_trust_boundaries(self) -> None:
        a = self._result.analysis
        s = self._result.security

        if not a.egress.outbound_calls:
            return

        self._heading("Trust Boundaries -- What Leaves This Repo")
        self._heading("Data Egress", 3)
        for call in a.egress.outbound_calls:
            domains = ", ".join(call.domains) if call.domains else "unknown"
            loc = f" ({call.evidence[0].file}:{call.evidence[0].line})" if call.evidence else ""
            self._bullet(f"{call.kind} via {call.library} -> {domains}{loc}")
        self._pdf.ln(2)

    # ── 3b. LLM Prompt Analysis ─────────────────────────────────────────

    def _render_prompt_surfaces(self) -> None:
        ps = self._result.analysis.prompt_surface
        if not ps.surfaces:
            return

        self._heading("LLM Prompt Analysis")

        headers = ["Function", "Method", "Variables", "Constants", "Location"]
        self._table_header(_PROMPT_COLS, headers)

        for i, s in enumerate(ps.surfaces):
            vars_str = ", ".join(v.name for v in s.prompt_variables[:5]) or "-"
            consts_str = ", ".join(s.string_constants[:3]) or "-"
            self._table_row(_PROMPT_COLS, [
                s.function, s.llm_method, vars_str, consts_str,
                f"{s.file}:{s.line}",
            ], i)

        self._pdf.ln(3)

    # ── 3c. Tool Registration Map ────────────────────────────────────────

    def _render_tool_registrations(self) -> None:
        tr = self._result.analysis.tool_registration
        if not tr.tools:
            return

        self._heading("Registered Tools")

        headers = ["Tool", "Registration", "Parameters", "Capabilities", "Location"]
        self._table_header(_TOOL_COLS, headers)

        for i, t in enumerate(tr.tools):
            params = ", ".join(t.parameters[:5]) or "-"
            caps = ", ".join(c.kind for c in t.capabilities) or "compute"
            self._table_row(_TOOL_COLS, [
                t.name, t.registration, params, caps,
                f"{t.file}:{t.line}",
            ], i)

        self._pdf.ln(3)

    # ── 3d. State Flow ───────────────────────────────────────────────────

    def _render_state_flow(self) -> None:
        sf = self._result.analysis.state_flow
        if not sf.node_flows:
            return

        self._heading("State Flow")

        if sf.state_class:
            self._set_body_text()
            keys_str = ", ".join(sf.state_keys)
            self._pdf.multi_cell(
                self._content_w, 4.5,
                self._safe(f"State class: {sf.state_class} with keys: {keys_str}"),
                new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT,
            )
            self._pdf.ln(2)

        headers = ["Node", "Reads", "Writes", "Location"]
        self._table_header(_STATE_COLS, headers)

        for i, nf in enumerate(sf.node_flows):
            reads = ", ".join(nf.reads[:5]) or "-"
            writes = ", ".join(nf.writes[:5]) or "-"
            self._table_row(_STATE_COLS, [
                nf.function, reads, writes,
                f"{nf.file}:{nf.line_start}",
            ], i)

        self._pdf.ln(3)

    # ── 4. Entrypoint effect matrix ────────────────────────────────────

    def _render_entrypoint_matrix(self) -> None:
        p = self._result.projection
        if not p or not p.projections:
            return

        self._heading("Entrypoint Effect Matrix")

        headers = ["Entrypoint", "Reach", "Reads", "Writes", "Sends", "Secrets", "PII", "LLM", "Prompts", "Tools"]
        self._table_header(_MATRIX_COLS, headers)

        for row_idx, ep in enumerate(p.projections):
            reads = writes = sends = secrets = pii = llm = prompts = tools = 0
            for eff in ep.effects:
                src = eff.source.lower()
                title_lower = eff.title.lower()
                if src == "io":
                    if "read" in title_lower or "input" in title_lower:
                        reads += 1
                    elif "write" in title_lower or "output" in title_lower or "artifact" in title_lower:
                        writes += 1
                elif src == "egress":
                    if "llm" in title_lower:
                        llm += 1
                    else:
                        sends += 1
                elif src == "secret":
                    secrets += 1
                elif src == "security":
                    if "pii" in title_lower:
                        pii += 1
                elif src == "prompt":
                    prompts += 1
                elif src == "tool":
                    tools += 1

            reachable = len(ep.reachable_functions)
            self._table_row(_MATRIX_COLS, [
                ep.entrypoint_label, str(reachable), str(reads), str(writes),
                str(sends), str(secrets), str(pii), str(llm), str(prompts), str(tools),
            ], row_idx)

        self._pdf.ln(3)

        if p.unreachable_findings:
            self._set_body_text()
            self._pdf.set_text_color(*_MUTED)
            self._pdf.cell(
                self._content_w, 5,
                self._safe(f"{len(p.unreachable_findings)} finding(s) outside call graph (config files, unused code)"),
                new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT,
            )
            self._pdf.ln(3)

    # ── 5. Security findings ───────────────────────────────────────────

    def _render_security_findings(self) -> None:
        s = self._result.security
        if not s:
            return

        if not s.findings and not s.data_classifications:
            return

        self._divider()
        self._heading("Security Findings")

        # All findings in one sorted pass — category-specific inline extras per type
        if s.findings:
            for f in sorted(s.findings, key=lambda x: (sev_order(x.severity), x.category)):
                self._ensure_space(25)
                title = strip_bandit_prefix(f.title)
                self._severity_badge(f.severity)
                self._pdf.set_font("Helvetica", "B", 10)
                self._pdf.set_text_color(*_BODY)
                self._pdf.cell(self._content_w - 25, 5, self._safe(title), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
                self._pdf.ln(1)

                self._pdf.set_font("Helvetica", "", 8)
                self._pdf.set_text_color(*_MUTED)
                self._pdf.cell(self._content_w, 4, self._safe(f"Category: {f.category}"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

                self._set_body_text()
                self._pdf.multi_cell(self._content_w, 4, self._safe(f.description), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

                # Category-specific inline details
                if f.category == "data_flow" and f.data_sink:
                    pii = ", ".join(f.pii_fields) if f.pii_fields else "none"
                    self._pdf.set_font("Helvetica", "", 8)
                    self._pdf.set_text_color(*_MUTED)
                    self._pdf.multi_cell(
                        self._content_w, 4,
                        self._safe(f"Source: {f.data_source} | Sink: {f.data_sink} | PII: {pii}"),
                        new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT,
                    )
                elif f.category == "credential_leak" and f.credential_name:
                    self._pdf.set_font("Helvetica", "", 8)
                    self._pdf.set_text_color(*_MUTED)
                    self._pdf.cell(
                        self._content_w, 4,
                        self._safe(f"Credential: {f.credential_name} -> {leak_label(f.leak_target or '')}"),
                        new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT,
                    )

                if f.recommendation:
                    self._pdf.set_font("Helvetica", "I", 8)
                    self._pdf.set_text_color(*_MUTED)
                    self._pdf.multi_cell(self._content_w, 4, self._safe(f"Recommendation: {f.recommendation}"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

                if f.evidence:
                    self._pdf.set_font("Courier", "", 7.5)
                    self._pdf.set_text_color(*_MUTED)
                    for e in f.evidence:
                        self._pdf.set_x(19)
                        self._pdf.multi_cell(self._content_w - 4, 3.5, self._safe(f"{e.file}:{e.line}  {e.snippet}"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

                self._pdf.ln(3)

        # Data classifications
        if s.data_classifications:
            self._heading("Data Classifications", 3)
            for dc in s.data_classifications:
                fields = ", ".join(dc.fields_detected[:10])
                self._bullet(f"{dc.category} ({dc.confidence:.0%}): {fields}")
            self._pdf.ln(2)

        # Per-entrypoint effect tables
        p = self._result.projection
        if p and p.projections:
            self._heading("Per-Entrypoint Details", 3)
            for ep in p.projections:
                self._heading(ep.entrypoint_label, 4)
                self._set_body_text()
                self._pdf.cell(self._content_w, 4, self._safe(f"Reachable functions: {len(ep.reachable_functions)}"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
                self._pdf.ln(1)

                if ep.effects:
                    headers = ["Source", "Effect", "Severity", "Location"]
                    self._table_header(_EFFECT_COLS, headers)
                    for i, eff in enumerate(sorted(ep.effects, key=lambda x: sev_order(x.severity))):
                        fn = f" ({eff.function_name})" if eff.function_name else ""
                        self._table_row_with_badge(
                            _EFFECT_COLS,
                            [eff.source, strip_bandit_prefix(eff.title), eff.severity, f"{eff.file}:{eff.line}{fn}"],
                            i, badge_col=2, badge_sev=eff.severity,
                        )
                    self._pdf.ln(3)
                else:
                    self._pdf.set_text_color(*_MUTED)
                    self._pdf.cell(self._content_w, 4, "No projected effects.", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
                    self._pdf.ln(2)

            if p.unreachable_findings:
                self._heading("Findings Outside Call Graph", 4)
                headers = ["Source", "Effect", "Severity", "Location"]
                self._table_header(_EFFECT_COLS, headers)
                for i, eff in enumerate(sorted(p.unreachable_findings, key=lambda x: sev_order(x.severity))):
                    fn = f" ({eff.function_name})" if eff.function_name else ""
                    self._table_row_with_badge(
                        _EFFECT_COLS,
                        [eff.source, strip_bandit_prefix(eff.title), eff.severity, f"{eff.file}:{eff.line}{fn}"],
                        i, badge_col=2, badge_sev=eff.severity,
                    )
                self._pdf.ln(3)

    # ── 6. Call graph (text tree) ──────────────────────────────────────

    def _render_call_graph(self) -> None:
        p = self._result.projection
        if not p or not p.call_graph or not p.call_graph.edges:
            return

        self._heading("Call Graph")

        # Build adjacency list
        children: dict[str, list[str]] = {}
        for edge in p.call_graph.edges:
            children.setdefault(edge.caller, []).append(edge.callee)

        # Build id -> function name + file map
        fn_info: dict[str, tuple[str, str]] = {}
        for fn in p.call_graph.functions:
            fn_info[fn.id] = (fn.name, fn.file)

        # Render tree from each entrypoint, depth-limited to 3
        entrypoint_ids = set(p.call_graph.entrypoint_ids)
        for ep_id in p.call_graph.entrypoint_ids:
            name, file = fn_info.get(ep_id, (ep_id, ""))
            self._ensure_space(10)
            self._pdf.set_font("Courier", "B", 8)
            self._pdf.set_text_color(*_BODY)
            self._pdf.cell(self._content_w, 4, self._safe(f"{name} ({file})"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            visited: set[str] = {ep_id}
            self._render_tree_children(ep_id, children, fn_info, visited, depth=1, max_depth=3)
            self._pdf.ln(2)

    def _render_tree_children(self, node_id: str, children: dict[str, list[str]],
                               fn_info: dict[str, tuple[str, str]],
                               visited: set[str], depth: int, max_depth: int) -> None:
        if depth > max_depth:
            return
        # Deduplicate children (same callee may appear multiple times)
        seen_kids: set[str] = set()
        unique_kids: list[str] = []
        for kid in children.get(node_id, []):
            if kid not in seen_kids:
                seen_kids.add(kid)
                unique_kids.append(kid)

        for i, child_id in enumerate(unique_kids):
            name, file = fn_info.get(child_id, (child_id, ""))
            is_last = i == len(unique_kids) - 1
            connector = "|-- " if not is_last else "'-- "
            self._ensure_space(5)
            self._pdf.set_font("Courier", "", 7.5)
            self._pdf.set_text_color(*_MUTED)
            self._pdf.set_x(15 + depth * 4)
            self._pdf.cell(self._content_w - depth * 4, 3.5, self._safe(f"{connector}{name} ({file})"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            # Recurse into subtree only if not already expanded elsewhere
            if child_id not in visited:
                visited.add(child_id)
                self._render_tree_children(child_id, children, fn_info, visited, depth + 1, max_depth)

    # ── 7. Project structure ───────────────────────────────────────────

    def _render_structural_summary(self) -> None:
        a = self._result.analysis

        self._divider()
        self._heading("Project Structure")

        # Basic info
        archetypes = ", ".join(f"{at.type} ({at.confidence:.0%})" for at in a.detection.archetypes) or "none"
        self._kv("Project", str(self._result.project_path))
        self._kv("Archetypes", archetypes)
        self._kv("Python files", count_py_files(a))
        self._kv("Dependencies", str(len(a.deps.dependencies)))
        self._pdf.ln(2)

        # Entrypoints
        if a.detection.entrypoint_candidates:
            self._heading("Entrypoints", 3)
            for c in a.detection.entrypoint_candidates:
                loc = f" ({c.evidence[0].file})" if c.evidence else ""
                self._bullet(f"{c.value} ({c.kind}, {c.confidence:.0%}{loc})")
            self._pdf.ln(2)

        # Dependencies
        if a.deps.dependencies:
            self._heading("Dependencies", 3)
            dep_names = [d.name for d in a.deps.dependencies[:20]]
            dep_str = ", ".join(dep_names)
            if len(a.deps.dependencies) > 20:
                dep_str += f" ... +{len(a.deps.dependencies) - 20} more"
            if a.deps.python_version_hint:
                dep_str += f" (Python {a.deps.python_version_hint})"
            self._set_body_text()
            self._pdf.multi_cell(self._content_w, 4.5, self._safe(dep_str), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            self._pdf.ln(2)

        # I/O
        if a.io.inputs or a.io.outputs:
            if a.io.inputs:
                self._heading("Inputs", 3)
                for inp in a.io.inputs[:10]:
                    self._bullet(f"{inp.id} ({inp.kind})")
            if a.io.outputs:
                self._heading("Outputs", 3)
                for out in a.io.outputs[:10]:
                    self._bullet(f"{out.id} ({out.kind})")
            self._pdf.ln(2)

        # Hardcoded paths
        if a.io.hardcoded_paths:
            self._heading("Hardcoded paths", 3)
            for hp in a.io.hardcoded_paths[:5]:
                self._bullet(hp.path)
            if len(a.io.hardcoded_paths) > 5:
                self._set_body_text()
                self._pdf.set_text_color(*_MUTED)
                self._pdf.cell(self._content_w, 4, self._safe(f"... +{len(a.io.hardcoded_paths) - 5} more"), new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
            self._pdf.ln(2)

        # API routes
        if a.io.api_routes:
            self._heading("API routes", 3)
            for r in a.io.api_routes[:10]:
                self._bullet(f"{r.method} {r.path}")
            self._pdf.ln(2)

        # Egress
        if a.egress.outbound_calls:
            self._heading("External connections", 3)
            for c in a.egress.outbound_calls[:10]:
                self._bullet(f"{c.library} ({c.kind})")
            self._pdf.ln(2)

        self._set_body_text()
        self._pdf.set_text_color(*_MUTED)
        self._pdf.set_font("Helvetica", "I", 8)
        self._pdf.cell(self._content_w, 4, "For full structural details, use --format json", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.ln(3)

    # ── Appendix: Audit Trail ─────────────────────────────────────────

    def _render_toolchain_appendix(self) -> None:
        if not self._result.toolchain:
            return

        self._divider()

        self._pdf.set_font("Helvetica", "", 8)
        self._pdf.set_text_color(*_MUTED)
        self._pdf.cell(self._content_w, 4, "Appendix: Audit Trail", new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)
        self._pdf.ln(2)

        self._heading("Scan Toolchain", 3)
        headers = ["Tool", "Version", "Status", "Findings", "What It Checks"]
        self._table_header(_TOOLCHAIN_COLS, headers)

        # Status color mapping
        status_colors = {
            "ran": (22, 101, 52),
            "skipped": (161, 120, 0),
            "not_installed": (194, 80, 0),
            "error": (185, 28, 28),
        }

        for i, t in enumerate(self._result.toolchain):
            findings_str = str(t.findings) if t.findings >= 0 else "-"
            self._ensure_space(8)
            if i % 2 == 1:
                self._pdf.set_fill_color(*_ALT_ROW)
                fill = True
            else:
                fill = False

            y_start = self._pdf.get_y()
            # Tool name
            self._pdf.set_font("Helvetica", "B", 7.5)
            self._pdf.set_text_color(*_BODY)
            self._pdf.cell(_TOOLCHAIN_COLS[0], 5.5, self._safe(t.name), border=0, fill=fill, new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            # Version
            self._pdf.set_font("Helvetica", "", 7.5)
            self._pdf.cell(_TOOLCHAIN_COLS[1], 5.5, self._safe(t.version), border=0, fill=fill, new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            # Status (color-coded)
            sc = status_colors.get(t.status, _BODY)
            self._pdf.set_text_color(*sc)
            self._pdf.set_font("Helvetica", "B", 7.5)
            self._pdf.cell(_TOOLCHAIN_COLS[2], 5.5, self._safe(t.status), border=0, fill=fill, new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            # Findings
            self._pdf.set_text_color(*_BODY)
            self._pdf.set_font("Helvetica", "", 7.5)
            self._pdf.cell(_TOOLCHAIN_COLS[3], 5.5, findings_str, border=0, fill=fill, new_x=self._XPos.RIGHT, new_y=self._YPos.TOP)
            # Description
            self._pdf.cell(_TOOLCHAIN_COLS[4], 5.5, self._safe(t.description), border=0, fill=fill, new_x=self._XPos.LMARGIN, new_y=self._YPos.NEXT)

        self._pdf.ln(3)

