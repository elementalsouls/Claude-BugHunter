#!/usr/bin/env python3
"""Generate a self-hosted star-history chart (light + dark SVG).

Why this exists: star-history.com and starchart.cc are third-party services that
return 500s and rate-limit errors, which silently blanks the README chart. This
renders the same chart from GitHub's own API and commits the result, so the
README has no external runtime dependency.

Usage:
    gh auth login                      # once
    python3 scripts/gen_star_history.py [owner/repo]

Writes assets/star-history-light.svg and assets/star-history-dark.svg.
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = sys.argv[1] if len(sys.argv) > 1 else "elementalsouls/Claude-BugHunter"
OUT = Path(__file__).resolve().parent.parent / "assets"

# Validated with the dataviz palette validator against GitHub's real surfaces:
# light #ffffff, dark #0d1117 — lightness band, chroma floor and contrast all PASS.
THEMES = {
    "light": dict(accent="#c81e3c", ink="#1f2328", muted="#59636e",
                  grid="#d1d9e0", surface="none"),
    "dark":  dict(accent="#ff2d4f", ink="#e6edf3", muted="#9198a1",
                  grid="#2a313c", surface="none"),
}

W, H = 840, 400
PAD_L, PAD_R, PAD_T, PAD_B = 62, 30, 30, 44


def fetch_stars(repo):
    """Page GitHub's stargazers API for starred_at timestamps."""
    stamps, page = [], 1
    while True:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/stargazers?per_page=100&page={page}",
             "-H", "Accept: application/vnd.github.star+json", "--jq", ".[].starred_at"],
            capture_output=True, text=True,
        )
        # Distinguish a real end-of-data (rc 0, empty array) from a transient
        # failure (rate-limit / 5xx → rc != 0). Without this, a failed page
        # looks like "no more stars" and we'd render+commit a truncated chart
        # with a lower count. Abort instead, leaving the committed SVGs intact.
        if out.returncode != 0:
            sys.exit(f"stargazers fetch failed at page {page}: {out.stderr.strip()}")
        got = [l for l in out.stdout.split("\n") if l.strip()]
        if not got:
            break
        stamps.extend(got)
        page += 1
        if page > 400:  # GitHub pagination ceiling
            break
    return sorted(stamps)


def build_series(stamps):
    """Cumulative count per day."""
    days = {}
    for s in stamps:
        d = s[:10]
        days[d] = days.get(d, 0) + 1
    series, total = [], 0
    for d in sorted(days):
        total += days[d]
        series.append((datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc), total))
    return series


def nice_ticks(hi, count=4):
    """Round y-axis ticks to a readable step."""
    raw = hi / count
    mag = 10 ** (len(str(int(raw))) - 1)
    for m in (1, 2, 2.5, 5, 10):
        if mag * m >= raw:
            step = mag * m
            break
    else:
        step = mag * 10
    # the top tick must be >= hi, or the series escapes the plot area
    ticks, v = [], 0
    while v < hi:
        ticks.append(int(v))
        v += step
    ticks.append(int(v))
    return ticks


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(series, theme_name):
    t = THEMES[theme_name]
    t0, t1 = series[0][0], series[-1][0]
    span = max((t1 - t0).total_seconds(), 1)
    hi = series[-1][1]
    ticks = nice_ticks(hi)
    ymax = ticks[-1]

    def X(dt):
        return PAD_L + (dt - t0).total_seconds() / span * (W - PAD_L - PAD_R)

    def Y(v):
        return H - PAD_B - (v / ymax) * (H - PAD_T - PAD_B)

    pts = [(X(d), Y(v)) for d, v in series]
    line = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = line + f" L{pts[-1][0]:.1f},{H - PAD_B} L{pts[0][0]:.1f},{H - PAD_B} Z"

    font = ("system-ui,-apple-system,'Segoe UI',Roboto,"
            "'Helvetica Neue',Arial,sans-serif")
    o = []
    a = o.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
      f'viewBox="0 0 {W} {H}" role="img" '
      f'aria-label="Star history for {esc(REPO)}: {hi} stars as of {t1:%d %b %Y}">')
    a(f'<title>Star history for {esc(REPO)}</title>')
    a(f'<defs><linearGradient id="fill-{theme_name}" x1="0" y1="0" x2="0" y2="1">'
      f'<stop offset="0%" stop-color="{t["accent"]}" stop-opacity="0.22"/>'
      f'<stop offset="100%" stop-color="{t["accent"]}" stop-opacity="0.02"/>'
      f'</linearGradient></defs>')

    # recessive grid + y labels (tabular figures so digits align)
    for v in ticks:
        y = Y(v)
        a(f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{W - PAD_R}" y2="{y:.1f}" '
          f'stroke="{t["grid"]}" stroke-width="1"/>')
        a(f'<text x="{PAD_L - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="{font}" '
          f'font-size="12" font-variant-numeric="tabular-nums" fill="{t["muted"]}">{v:,}</text>')

    # x labels: first, middle, last — anchored so the outer two never overrun the canvas
    xlabels = ((series[0][0], "start"), (series[len(series) // 2][0], "middle"), (t1, "end"))
    for dt, anchor in xlabels:
        x = X(dt)
        if anchor == "start":
            x -= 4
        elif anchor == "end":
            x += 4
        a(f'<text x="{x:.1f}" y="{H - PAD_B + 22:.1f}" text-anchor="{anchor}" '
          f'font-family="{font}" font-size="12" fill="{t["muted"]}">{dt:%d %b %Y}</text>')

    a(f'<path d="{area}" fill="url(#fill-{theme_name})"/>')
    a(f'<path d="{line}" fill="none" stroke="{t["accent"]}" stroke-width="2" '
      f'stroke-linejoin="round" stroke-linecap="round"/>')

    # emphasised endpoint — the only labelled point
    ex, ey = pts[-1]
    a(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="4.5" fill="{t["accent"]}"/>')
    lx = min(ex + 12, W - PAD_R - 4)
    anchor = "end" if ex + 12 > W - PAD_R - 60 else "start"
    a(f'<text x="{lx:.1f}" y="{max(ey - 12, PAD_T + 12):.1f}" text-anchor="{anchor}" '
      f'font-family="{font}" font-size="15" font-weight="600" '
      f'font-variant-numeric="tabular-nums" fill="{t["ink"]}">{hi:,} stars</text>')

    # title names the series, so no legend box is needed
    a(f'<text x="{PAD_L}" y="20" font-family="{font}" font-size="13" '
      f'font-weight="600" fill="{t["ink"]}">{esc(REPO)} — stars over time</text>')
    a("</svg>")
    return "\n".join(o)


def main():
    print(f"fetching stargazers for {REPO} …")
    stamps = fetch_stars(REPO)
    if not stamps:
        sys.exit("no stargazer data returned — is `gh` authenticated?")
    series = build_series(stamps)
    print(f"  {len(stamps):,} stars, {series[0][0]:%Y-%m-%d} → {series[-1][0]:%Y-%m-%d}")
    OUT.mkdir(exist_ok=True)
    for name in THEMES:
        p = OUT / f"star-history-{name}.svg"
        p.write_text(render(series, name))
        print(f"  wrote {p.relative_to(OUT.parent)} ({p.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
