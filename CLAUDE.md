# CLAUDE.md

Context for Claude Code working in this repo. Read this before changing `plexreport.py`.

## What this is

A single-file tool that reads Plex Media Server logs and writes one self-contained HTML
report: findings ranked by severity, an hourly activity band, statistics, playback and
transcode detail, HTTP breakdown, errors grouped by message pattern, and a coverage
section. Optional PDF and JSON output.

Everything lives in `plexreport.py`. That is deliberate — it gets copied onto servers and
run with `python3 plexreport.py`, so it must stay one file.

## Hard constraints

- **Standard library only.** No pip dependencies, ever. Python 3.8+.
- **Single file.** Don't split into a package.
- **Self-contained HTML.** No CDN links, no external fonts, no build step. Inline CSS,
  inline SVG, a few lines of vanilla JS. It has to work offline and behind a proxy.
- **No browser storage** in the output.
- **Streaming aggregation.** Logs run to hundreds of MB. Keep counters and bounded
  samples, never a list of every parsed line.

## The rule that matters most

**Verify against real log output; never assume.** Every format and message pattern in
this file was checked against actual Plex logs before being written. If you are adding a
pattern and cannot point at a real line it matches, it does not go in — or it goes in and
the report shows it firing zero times, which is why the coverage section exists.

Corollary: when the tool cannot determine something, it says so rather than guessing. An
empty section means "no evidence in these logs", not "zero".

## Verified facts, so you don't re-derive them

These were established by inspecting real logs. Changing code that depends on them
without new evidence will reintroduce bugs that were already fixed once.

**Three line formats.** The regexes in `FORMATS` cover:

```
Sep 10, 2026 10:43:45.295 [22509839989560] DEBUG - [Req#1c90] message   # current
May 24, 2017 12:02:51.295 [0x80ac72c00] VERBOSE - message               # older builds
Sep 21, 2014 21:22:52 [0x809a91c00] DEBUG - message                     # no millis
2026-09-10 10:35:24,362 (149700cca808) :  INFO (core:349) - message     # plugin framework
```

Format is sniffed per file by best-match count, not assumed from the filename.

**`Plex Transcoder Statistics*.log` is XML, not lines.** One `<SessionReport>` per file,
with `User`, `Player`, `Variants/Variant/Media`, and a `SegmentList`. Parsed by
`parse_sessions()`.

**The version banner does not mean a restart.** Plex reprints
`Plex Media Server v… - …` at the top of *every rotated log*. Rotation is size-based at
10 MiB. Counting banners over-reports restarts by the number of rotations. Real starts are
detected by `RE_STARTUP`, and only in files classified `Media Server` — the scanner opens
the database too, and `Opening N database sessions to library` also fires for the EPG
database, which is why that pattern is pinned to `com.plexapp.plugins.library`.

**Decoder errors are logged at ERROR and dominate the count.** ffmpeg complaints from
inside the transcoder (`ac-tex damaged`, `mb incr damaged`, `Warning MVs not available`)
ran 27,836 of 28,510 errors in the sample that drove development. They are grouped
separately by `classify_group` and excluded from the main message table, or they drown
everything that matters.

**Segment timelines measure pacing, not encoder work.** Each `Segment`'s
`Timelines/Transcode` interval is the wall-clock window that segment was completed in, and
the windows tile the session end to end with no gaps. For a live source, ~1 s of wall per
1 s of media is the *ceiling* and means the transcoder kept up. Dividing media duration by
total session wall-clock produces a number below 1.0 that looks like a performance
problem and is not. Long windows mean the source stalled; the encoder is idle during them.
This was shipped wrong once — don't reintroduce a "speed" ratio.

**Request and timeline lines are DEBUG.** `Completed:`/`Request:`/`/:/timeline` only exist
when debug logging is on. Sections built on them must degrade to an explicit "not logged"
message, not to zeros.

## Performance landmines

Two regexes caused catastrophic backtracking on real lines and hung the first run
entirely. Both are fixed; the shapes to avoid are:

```python
# BAD - nested quantifier with optional inner parts, hangs on long non-matching lines
re.compile(r"\[(?:[a-z0-9_]+:?\d*[:/]?)*[a-z0-9_]+ @ 0x[0-9a-f]+\]")
# GOOD - bounded, no ambiguity
re.compile(r"\[[^\]\[]{1,60} @ 0x[0-9a-f]+\]")
```

Rule of thumb: no `(...)*` or `(...){2,}` where the inner group can match the same text
several ways. Bound every repetition and exclude the delimiter from the character class.

Also: `classify_group()` and `signature()` run only on WARN/ERROR lines. A small
pre-filter, `NOTABLE_AT_ANY_LEVEL`, lets a handful of sub-warning conditions reach the
findings table without running 17 regexes over every DEBUG line. Keep the hot path cheap.

## Code map

| Area | What's there |
|---|---|
| `FORMATS`, `detect_format` | line-format sniffing |
| `iter_sources`, `classify_file`, `rotation_key` | zip/dir/gz discovery, file typing |
| `signature`, `GROUPS`, `classify_group` | message normalization and bucketing |
| `FINDINGS` | the rule table — id, severity, pattern, meaning, check |
| `Agg`, `handle_line`, `ingest` | the single streaming pass |
| `parse_sessions` | Transcoder Statistics XML |
| `viewing_sessions` | rebuilds watch sessions from timeline events |
| `CSS`, `render`, `activity_band`, `hourly_chart` | output |
| `to_json`, `write_pdf`, `main` | side outputs and CLI |

## Adding a findings rule

Append a dict to `FINDINGS` with `id`, `sev` (critical/high/medium/low/info), `title`,
compiled `pat`, `meaning` (what the log line reports, factually) and `check` (where to
look next). Keep `meaning` descriptive rather than diagnostic — say what Plex logged, not
what you think broke. If the condition is logged below WARN, add a keyword to
`NOTABLE_AT_ANY_LEVEL` too, or the rule will never see the line.

## Testing

There is no test framework. The sample generator is the test:

```bash
python3 examples/make_sample_logs.py examples/sample-logs
python3 plexreport.py examples/sample-logs -o /tmp/t.html --json /tmp/t.json
```

Expected: all 17 findings fire, 0 unparsed lines, 2 transcode sessions. If you add a rule,
add a line to `make_sample_logs.py` that triggers it, so the count goes up and stays
honest. The generated logs are fictional and deterministic (`random.seed`).

Check rendering at 390px and 1280px if you touch `CSS` or the chart functions. Charts use
`preserveAspectRatio="none"` with a fixed CSS height, so **no `<text>` inside the SVG** —
it distorts. Labels go in the HTML caption below.

The PDF path may run through wkhtmltopdf, whose engine has no CSS grid support, hence the
`inline-block` fallback under `@supports (display:grid)`. Don't remove it.

## Privacy

Auth tokens are masked unconditionally in `scrub()`. `--redact` adds IPs, accounts and
emails. Media titles, device names and channel identifiers are *not* masked by either —
mention that rather than implying `--redact` makes a report safe to publish. Never commit
real logs or real reports; `.gitignore` blocks both.

## Possible next steps

- Read `com.plexapp.plugins.library.db` for actual watch history (`metadata_item_views`,
  `statistics_media`, `statistics_bandwidth`). Read-only, on a copy, `sqlite3` from the
  stdlib. This is where real statistics live — the logs only approximate them.
- Trend mode: diff two `summary.json` files and report what changed.
- More findings rules as new message shapes show up in the coverage section.
