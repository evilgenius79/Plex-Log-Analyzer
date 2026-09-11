#!/usr/bin/env python3
"""
plexreport.py - turn Plex Media Server logs into a readable HTML (or PDF) report.

Stdlib only, no dependencies. Python 3.8+. See README.md for the long version.

  python3 plexreport.py "Plex Media Server Logs.zip" -o report.html
  python3 plexreport.py /path/to/Logs -o report.html --since 48h
  python3 plexreport.py logs.zip -o report.html --redact      # mask IPs/users/emails
  python3 plexreport.py logs.zip -o report.html --pdf report.pdf
  python3 plexreport.py logs.zip -o report.html --json summary.json

Accepts the zip from Plex Web (Settings > Manage > Troubleshooting > Download Logs),
a Logs directory (recursed, incl. "PMS Plugin Logs"), or individual .log/.gz files.
Transcoder Statistics files are XML session reports and are parsed as such.

The report contains: a findings list ranked by severity, an hourly activity band,
statistics (viewing sessions, data served, response times, playback states, live TV
sources), playback and transcode session detail, HTTP request breakdown, errors
grouped by message pattern, maintenance, library scans, and a coverage section.

HOW TO TRUST THE OUTPUT
  * Line formats are sniffed, never assumed. Every file reports the format that
    matched and its parse rate, in the "Files read" section.
  * Message-level extraction is a table of rules (FINDINGS / classify_group).
    Rules that never fired are listed in the report, and the most common message
    shapes that no rule matched are listed too - gaps are visible, not silent.
  * Every claim in the report traces back to counted log lines with timestamps.
  * Traffic and viewing-session statistics come from "Completed:" / "/:/timeline"
    lines, which Plex writes at DEBUG level. With debug logging off those sections
    are legitimately empty rather than zero.
"""

import argparse
import gzip
import html
import io
import json
import os
import re
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta

VERSION = "1.2"

# ---------------------------------------------------------------------------
# Line formats  (all three verified against real Plex output)
# ---------------------------------------------------------------------------
#  pms     Sep 10, 2026 10:43:45.295 [22509839989560] DEBUG - [Req#1c90] message
#          May 24, 2017 12:02:51.295 [0x80ac72c00] VERBOSE - message      (old builds)
#          Sep 21, 2014 21:22:52 [0x809a91c00] DEBUG - message            (no millis)
#  plugin  2026-09-10 10:35:24,362 (149700cca808) :  INFO (core:349) - message
#  iso     generic fallback for side-car logs

FORMATS = [
    ("pms", re.compile(
        r"^(?P<ts>[A-Z][a-z]{2} +\d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
        r"\s+\[(?P<thread>[^\]]*)\]\s+(?P<level>[A-Za-z]+)\s+-\s?(?P<msg>.*)$"),
     ("%b %d, %Y %H:%M:%S.%f", "%b %d, %Y %H:%M:%S")),

    ("plugin", re.compile(
        r"^(?P<ts>\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{2}:\d{2},\d{1,3})"
        r"\s+\((?P<thread>[0-9a-fA-F]+)\)\s*:\s*(?P<level>[A-Za-z]+)"
        r"(?:\s+\((?P<src>[^)]*)\))?\s+-\s?(?P<msg>.*)$"),
     ("%Y-%m-%d %H:%M:%S,%f",)),

    ("iso", re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
        r"\s*(?:Z|[+-]\d{2}:?\d{2})?\s*[-:\[]?\s*"
        r"(?P<level>TRACE|DEBUG|VERBOSE|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL)\]?"
        r"\s*[-:]?\s?(?P<msg>.*)$", re.I),
     ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
      "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")),
]

LEVELS = ["FATAL", "CRITICAL", "ERROR", "WARN", "INFO", "DEBUG", "VERBOSE", "TRACE", "OTHER"]
LEVEL_ALIAS = {"WARNING": "WARN", "NOTICE": "INFO", "CRIT": "CRITICAL", "ERR": "ERROR"}
BAD = {"FATAL", "CRITICAL", "ERROR"}

CONTEXT_RE = re.compile(r"^\[((?:Req#)?[^\]\[]{1,240})\]\s*(.*)$", re.S)


def norm_level(raw):
    lv = (raw or "").upper()
    lv = LEVEL_ALIAS.get(lv, lv)
    return lv if lv in LEVELS else "OTHER"


def parse_ts(text, fmts):
    for f in fmts:
        try:
            return datetime.strptime(text, f)
        except ValueError:
            pass
    return None


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
TOKEN_RE = re.compile(r"((?:auth_token|X-Plex-Token|token)=)[^&\s\"'\]]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(Signed-in Token \()([^)]+)(\))")


def scrub(text, redact=False):
    """Tokens are always masked. Everything else only with --redact."""
    text = TOKEN_RE.sub(r"\1<token>", text)
    if redact:
        text = EMAIL_RE.sub("<email>", text)
        text = USER_RE.sub(r"\1<user>\3", text)
        text = IP_RE.sub(lambda m: mask_ip(m.group(0)), text)
    return text


def mask_ip(ip):
    parts = ip.split(".")
    try:
        first, second = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return ip
    private = (first in (10, 127) or (first == 192 and second == 168)
               or (first == 172 and 16 <= second <= 31)
               or (first == 169 and second == 254))
    if private:
        return ip                      # private/loopback is not identifying
    return "%d.%d.x.x" % (first, second)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
SKIP_DIRS = {".git", "__pycache__", "Cache", "Crash Reports"}
LOGNAME_RE = re.compile(r"\.log(\.\d+)?$|\.(txt|out|err)$", re.I)


def looks_like_log(name):
    base = os.path.basename(name)
    if base.startswith(".") or base.startswith("__MACOSX"):
        return False
    low = base[:-3] if base.lower().endswith(".gz") else base
    return bool(LOGNAME_RE.search(low))


def iter_sources(paths):
    for p in paths:
        if not os.path.exists(p):
            print("skip (not found): %s" % p, file=sys.stderr)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    if looks_like_log(full):
                        yield os.path.relpath(full, p).replace("\\", "/"), _file_src(full)
        elif zipfile.is_zipfile(p):
            zf = zipfile.ZipFile(p)
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if info.is_dir() or not looks_like_log(info.filename):
                    continue
                yield info.filename.replace("\\", "/"), _zip_src(zf, info)
        else:
            yield os.path.basename(p), _file_src(p)


def _file_src(path):
    def _open():
        return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")
    return _open


def _zip_src(zf, info):
    def _open():
        raw = zf.read(info)
        return gzip.GzipFile(fileobj=io.BytesIO(raw)) if info.filename.endswith(".gz") \
            else io.BytesIO(raw)
    return _open


def read_text(src):
    with src() as fh:
        return fh.read().decode("utf-8", "replace")


FILE_KINDS = [
    ("plex media server", "Media Server"),
    ("plex transcoder statistics", "Transcoder session reports"),
    ("plex media scanner chapter thumbnails", "Scanner: chapter thumbnails"),
    ("plex media scanner deep analysis", "Scanner: deep analysis"),
    ("plex media scanner analysis", "Scanner: analysis"),
    ("plex media scanner matcher", "Scanner: matcher"),
    ("plex media scanner credits", "Scanner: credits"),
    ("plex media scanner", "Scanner"),
    ("plex tuner service", "Tuner service (Live TV/DVR)"),
    ("plex update service", "Update service"),
    ("plex crash uploader", "Crash uploader"),
    ("plex dlna", "DLNA server"),
    ("plex relay", "Relay"),
    ("plex script host", "Script host"),
    ("plex thumbnail", "Thumbnail generator"),
]


def classify_file(name):
    low = name.replace("\\", "/").lower()
    if "pms plugin logs/" in low:
        return "Plugin / agent"
    base = os.path.basename(low)          # the directory name must not decide the kind
    for needle, label in FILE_KINDS:
        if needle in base:
            return label
    return "Other"


def rotation_key(name):
    """Sort rotated logs oldest-first: Name.5.log .. Name.1.log .. Name.log"""
    base = os.path.basename(name)
    if base.lower().endswith(".gz"):
        base = base[:-3]
    m = re.search(r"\.(\d+)\.log$|\.log\.(\d+)$", base, re.I)
    idx = int(m.group(1) or m.group(2)) if m else 0
    stem = re.sub(r"\.(\d+)\.log$|\.log\.(\d+)$", "", base, flags=re.I)
    return (os.path.dirname(name), stem, -idx)


# ---------------------------------------------------------------------------
# Message signatures and grouping
# ---------------------------------------------------------------------------
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HASH_RE = re.compile(r"\b[0-9a-f]{16,64}\b", re.I)
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
REQ_RE = re.compile(r"Req#[0-9a-f]+", re.I)
NUM_RE = re.compile(r"\d+")
PATH_RE = re.compile(r"(?:/[^\s/\]\[]{1,90}){2,}")

# ffmpeg/libav decoder chatter, e.g. "[mpeg2video @ 0x7f..] ac-tex damaged at 12 34"
DECODER_RE = re.compile(r"\[[^\]\[]{1,60} @ 0x[0-9a-f]+\]", re.I)


def signature(msg, keep_paths=False):
    ctx = ""
    m = CONTEXT_RE.match(msg)
    if m:                                   # "[Req#1c90/Transcode/<uuid>] rest of message"
        ctx, msg = "[" + m.group(1) + "] ", m.group(2)
    body = REQ_RE.sub("Req#", msg)
    if not keep_paths:
        body = PATH_RE.sub("<path>", body)
    s = ctx + body
    s = UUID_RE.sub("<id>", s)
    s = HASH_RE.sub("<id>", s)
    s = HEX_RE.sub("<addr>", s)
    s = REQ_RE.sub("Req#", s)
    s = NUM_RE.sub("#", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:220]


GROUPS = [
    ("Transcoder decoder", lambda m: bool(DECODER_RE.search(m)) or m.startswith("overread ")),
    ("Database", lambda m: "SQLITE" in m or "database disk image" in m
     or "database corruption" in m or "Database backup" in m
     or "Database optimization" in m or "sqlite3_statement" in m),
    ("Transcode / streaming", lambda m: "/Transcode" in m or "transcode" in m.lower()
     or "Streaming Resource" in m or m.startswith("MDE:")),
    ("Live TV / DVR", lambda m: "/Grabber/" in m or "hdhomerun" in m.lower()
     or "livetv" in m.lower() or "tuner" in m.lower() or "Recording" in m),
    ("Metadata / agents", lambda m: "MetadataAgent" in m or "metadata" in m.lower()
     or "Match request" in m),
    ("Scanner / analysis", lambda m: "Scanner" in m or "IndexFrame" in m
     or "UltraBlur" in m or "Analysis" in m),
    ("Maintenance (Butler)", lambda m: m.startswith("Butler:") or "Butler:" in m),
    ("HTTP / API", lambda m: m.startswith(("Request:", "Completed:", "QueryParser"))
     or "request handler" in m),
    ("Network / remote access", lambda m: m.startswith(("NAT:", "MyPlex:", "Relay:"))
     or "HttpClient" in m or "Couldn't connect" in m or "OCSP" in m),
]


def classify_group(msg):
    for name, test in GROUPS:
        try:
            if test(msg):
                return name
        except Exception:
            pass
    return "Other"


# ---------------------------------------------------------------------------
# Findings: named conditions worth a human's attention.
# Every pattern below was taken from lines that actually occur in Plex logs.
# 'meaning' states what the log line reports; 'check' is where to look next.
# ---------------------------------------------------------------------------
FINDINGS = [
    dict(id="db_corrupt", sev="critical",
         title="Library database reports corruption",
         pat=re.compile(r"database disk image is malformed|database corruption at line", re.I),
         meaning="SQLite is rejecting reads/writes against the main library database "
                 "(com.plexapp.plugins.library.db). Plex logs this when a page it reads "
                 "does not match what the file's structure says should be there.",
         check="Plex's own database repair, or restoring the most recent good copy from the "
               "Plug-in Support/Databases folder. Corruption on a container setup is often "
               "traced to the appdata volume - filesystem, cache pool, or an unclean shutdown."),
    dict(id="db_backup_failed", sev="critical",
         title="Nightly database backup is failing",
         pat=re.compile(r"failed its integrity check, not backing up|wasn't able to back up your database", re.I),
         meaning="Plex ran its scheduled backup, ran an integrity check first, and refused to "
                 "write a backup because the check failed. Each night this repeats, the newest "
                 "good backup on disk gets older.",
         check="How far back the existing backups in Plug-in Support/Databases go - that set is "
               "the recovery window, and it stops advancing while this repeats."),
    dict(id="db_fixup_failed", sev="high",
         title="Scheduled database maintenance aborting",
         pat=re.compile(r"Fixup threw an exception|Uncaught exception (?:starting generator|running subtask)|Exception inside transaction", re.I),
         meaning="Butler maintenance tasks (optimize, fixups, marker generation) are throwing "
                 "out mid-transaction rather than completing.",
         check="Whether these stop once the database problem above is resolved - they are "
               "downstream of it."),
    dict(id="transcode_dir", sev="high",
         title="Transcode directory is not writable",
         pat=re.compile(r"IsDirWritable: directory .* is not writable|IsFileWritable: failed to create file", re.I),
         meaning="Plex tried to write to its configured transcoder temp directory and could not "
                 "create files there.",
         check="The path named in the sample line against the container's volume mappings and "
               "the permissions on the host side of that mount."),
    dict(id="transcoder_killed", sev="high",
         title="Transcoder processes killed by signal",
         pat=re.compile(r"exit code for process \d+ is -9 \(signal: Killed\)", re.I),
         meaning="A Plex Transcoder child process was terminated with SIGKILL rather than "
                 "exiting on its own. Plex kills its own transcoders when a client stops, but "
                 "the kernel OOM killer produces the same line.",
         check="Container memory limits and host memory pressure at the timestamps listed, to "
               "separate normal stop-playback kills from out-of-memory kills."),
    dict(id="transcoder_crash", sev="high",
         title="Transcoder process crashed mid-playback",
         pat=re.compile(r"Conversion failed\. The transcoder process crashed", re.I),
         meaning="A playback session ended because the transcoder died, not because the client "
                 "stopped. The viewer sees playback stop.",
         check="Whether these line up with the decoder errors on the same source, and with "
               "hardware-transcode settings."),
    dict(id="server_crash", sev="high",
         title="Server session ended in a crash",
         pat=re.compile(r"Session Health - Status: crashed", re.I),
         meaning="The crash uploader recorded that the previous server session terminated "
                 "abnormally, with a minidump written.",
         check="The Crash Reports folder for the dump matching that version and timestamp."),
    dict(id="recording_failed", sev="medium",
         title="Recording or live stream failed at the tuner",
         pat=re.compile(r"Recording failed\. Please check your tuner or antenna", re.I),
         meaning="Plex ended a live TV or DVR session because the tuner stopped delivering a "
                 "usable stream.",
         check="Signal quality on the affected channel and whether the tuner was already "
               "serving another stream at that moment."),
    dict(id="source_stall", sev="medium",
         title="Live source stopped feeding mid-session",
         pat=re.compile(r"^__never__$"),   # raised from session reports, not log text
         meaning="Inside a transcode session, segments took far longer to complete than the "
                 "media they contain, which happens when nothing is arriving to transcode.",
         check="Signal on the channel in question. The encoder is idle during these, so this "
               "is not a transcoding capacity problem."),
    dict(id="tuner_unreachable", sev="medium",
         title="Tuner did not answer on the network",
         pat=re.compile(r"Couldn't connect to server.*discover\.json|discover\.json.*Couldn't connect", re.I),
         meaning="Plex's HTTP request to the tuner's discovery endpoint failed to connect.",
         check="Whether the tuner's IP changed, or whether it was rebooting/busy at that time."),
    dict(id="handler_exception", sev="medium",
         title="API requests failing with unhandled exceptions",
         pat=re.compile(r"Got exception from request handler", re.I),
         meaning="A client request reached Plex and the handler threw, so the client got an "
                 "error instead of data.",
         check="The status-code table below - these usually surface as 500s."),
    dict(id="index_failed", sev="low",
         title="Media index / thumbnail generation failing on some parts",
         pat=re.compile(r"buildIndexFile: part has no video stream|extraction has failed after multiple previous retry attempts|UltraBlurProcessor\] Failed", re.I),
         meaning="Plex could not build seek/preview data or extract colours for particular media "
                 "parts and gave up on them after retries.",
         check="The specific items named, if their previews or scrubbing look wrong in clients."),
    dict(id="agent_no_match", sev="low",
         title="Metadata lookups returning nothing",
         pat=re.compile(r"Match request for '.*' returned no metadata|Unable to find title for item of type", re.I),
         meaning="An agent queried its provider for a title and got no usable result back.",
         check="Naming of those items, or match them by hand."),
    dict(id="webhook_failed", sev="low",
         title="Webhook deliveries failing",
         pat=re.compile(r"Webhook: Error delivering payload", re.I),
         meaning="Plex tried to POST an event to a configured webhook URL and the delivery did "
                 "not succeed.",
         check="Whether the receiving service was up; failed deliveries are not retried."),
    dict(id="wal_recovery", sev="low",
         title="Database recovered from its write-ahead log at startup",
         pat=re.compile(r"recovered \d+ frames from WAL file", re.I),
         meaning="On start, SQLite found uncommitted pages in the write-ahead log and replayed "
                 "them. That happens when the previous run ended without closing the database - "
                 "a crash, a container kill, or a host that went down.",
         check="Whether this lines up with a crash or a container restart at the same time."),
    dict(id="plugin_framework", sev="low",
         title="Legacy plugin framework throwing exceptions",
         pat=re.compile(r"Private handlers are no longer supported|Exception in thread named|Exception getting hosted resource hashes", re.I),
         meaning="The old Python plugin framework that runs the bundled metadata agents is "
                 "logging exceptions and unsupported-handler messages at startup. This framework "
                 "is deprecated in current Plex builds and its agents are being retired.",
         check="Whether any library still uses a legacy .bundle agent rather than the current "
               "Plex agents; the noise is harmless on its own."),
    dict(id="decoder_noise", sev="info",
         title="Decoder errors while transcoding source video",
         pat=DECODER_RE,
         meaning="These come from the ffmpeg decoder inside the transcoder complaining about the "
                 "bitstream it was handed - damaged macroblocks, missing start codes, bad "
                 "motion vectors. With over-the-air MPEG-2 they track reception quality rather "
                 "than a fault in Plex, and Plex logs each one at ERROR, which is why the raw "
                 "error count is large.",
         check="The per-source breakdown below - errors concentrated on one channel or one file "
               "point at that source rather than the server."),
]


class Agg:
    """Everything the report needs, accumulated in one streaming pass."""

    def __init__(self, top=40, samples=4):
        self.top, self.nsamples = top, samples
        self.files = []
        self.levels = Counter()
        self.level_by_kind = defaultdict(Counter)
        self.bucket = defaultdict(Counter)        # datetime(hour) -> level counts
        self.sigs = {}                            # (level, sig) -> record
        self.groups = Counter()
        self.findings = {f["id"]: dict(f, count=0, first=None, last=None,
                                       samples=[], files=Counter(), sources=Counter())
                         for f in FINDINGS}
        self.http_status = Counter()
        self.http_endpoint = Counter()
        self.http_client = Counter()
        self.http_user = Counter()
        self.http_ms = Counter()           # response ms -> occurrences
        self.http_bytes = 0
        self.bytes_hour = Counter()
        self.req_hour = Counter()
        self.client_bytes = Counter()
        self.timeline = Counter()          # playing / paused / buffering / stopped
        self.timeline_hour = Counter()
        self.views = defaultdict(list)     # (ratingKey, client) -> [(ts, state)]
        self.item_titles = {}              # ratingKey -> title
        self.channels = Counter()
        self.added_items = []
        self.slow = []
        self.server_info = []
        self.starts = []
        self.opens = []
        self.jobs = Counter()
        self.job_events = []
        self.terminations = Counter()
        self.mde = Counter()
        self.mde_reason = Counter()
        self.play_users = Counter()
        self.play_devices = Counter()
        self.play_profiles = Counter()
        self.butler = Counter()
        self.scans = []
        self.sessions = []
        self.unmatched_shape = Counter()
        self.unparsed_lines = 0
        self.continuation_lines = 0
        self.total_lines = 0
        self.tmin = self.tmax = None
        self.core_min = self.core_max = None

    # -- helpers ----------------------------------------------------------
    def note_time(self, t, core=False):
        if t is None:
            return
        if core:
            if self.core_min is None or t < self.core_min:
                self.core_min = t
            if self.core_max is None or t > self.core_max:
                self.core_max = t
        if self.tmin is None or t < self.tmin:
            self.tmin = t
        if self.tmax is None or t > self.tmax:
            self.tmax = t

    def add_sig(self, level, msg, ts, fname, group):
        sig = signature(msg)
        key = (level, sig)
        rec = self.sigs.get(key)
        if rec is None:
            if len(self.sigs) > 20000:            # hard cap, keeps memory sane
                return
            rec = dict(level=level, sig=sig, group=group, count=0, first=ts, last=ts,
                       samples=[], files=Counter())
            self.sigs[key] = rec
        rec["count"] += 1
        rec["files"][fname] += 1
        if ts:
            if rec["first"] is None or ts < rec["first"]:
                rec["first"] = ts
            if rec["last"] is None or ts > rec["last"]:
                rec["last"] = ts
        if len(rec["samples"]) < self.nsamples:
            rec["samples"].append((ts, msg[:600]))

    def add_finding(self, msg, ts, fname, source_hint):
        for fid, rec in self.findings.items():
            if rec["pat"].search(msg):
                rec["count"] += 1
                rec["files"][fname] += 1
                if source_hint:
                    rec["sources"][source_hint] += 1
                if ts:
                    if rec["first"] is None or ts < rec["first"]:
                        rec["first"] = ts
                    if rec["last"] is None or ts > rec["last"]:
                        rec["last"] = ts
                if len(rec["samples"]) < self.nsamples:
                    rec["samples"].append((ts, msg[:500]))


# ---------------------------------------------------------------------------
# Line-level extraction rules (all patterns taken from observed Plex output)
# ---------------------------------------------------------------------------
RE_COMPLETED = re.compile(r"^Completed: \[([^\]]+)\] (\d{3}) ([A-Z]+) (\S+)")
RE_REQUEST = re.compile(r"^Request: \[([^\]\s]+)(?: \(([^)]+)\))?\] ([A-Z]+) (\S+)")
RE_MS = re.compile(r"\b(\d+)ms\b")
RE_BYTES = re.compile(r"\b(\d+) bytes\b")
RE_USER = re.compile(r"Signed-in Token \(([^)]+)\)")
RE_BANNER = re.compile(r"^Plex (Media Server|Media Scanner|Tuner Service) v(\S+) - (.*)$")
# Plex re-prints the version banner at the top of every rotated log, so a banner
# alone does NOT mean a restart. These lines only appear on a real start:
RE_STARTUP = re.compile(r"HttpServer: Listening on port \d+"
                        r"|Opening \d+ database sessions to library \(com\.plexapp\.plugins\.library\)"
                        r"|BPQ: \[Idle\] -> \[Starting\]")
RE_HOSTOS = re.compile(r"^(Linux|Windows|macOS) version: (.+?), language")
RE_JOB = re.compile(r"^Jobs: '([^']+)' exit code for process (\d+) is (-?\d+) \(([^)]+)\)")
RE_TERM = re.compile(r"Terminated session \S+ with reason (.+?)\.?$")
RE_MDE_TITLE = re.compile(r"MDE: (.+?): (no direct play|no remuxable|selected media|Direct Play|Cannot direct)")
RE_MDE_REASON = re.compile(r"MDE: (?:.+?: )?((?:no direct play|no remuxable|Cannot direct \w+|Direct Play is disabled)[^.]*)")
RE_NOW_USER = re.compile(r"\[Now\] User is (\S+) \(ID: (\d+)\)")
RE_NOW_DEV = re.compile(r"\[Now\] Device is ([^(]+?)\s*\(([^)]*)\)")
RE_NOW_PROFILE = re.compile(r"\[Now\] Profile is (\S+)")
RE_BUTLER = re.compile(r"^Butler: (?:Starting|Running|Scheduling randomized) (?:delayed )?task '?(\w+)'?")
RE_SCAN_CMD = re.compile(r"Plex Media Scanner (--\S+.*)$")
RE_TIMELINE = re.compile(r"/:/timeline\?")
RE_QS = re.compile(r"[?&](state|ratingKey|playbackTime|key|containerKey)=([^&\s]+)")
RE_ADDED = re.compile(r"^Added new metadata item \((.*?)\) with ID (\d+)")
RE_CHANNEL = re.compile(r"/Grabber/([\w.-]+?)-[0-9a-f]{12,}")

RE_ENDPOINT_ID = [
    (re.compile(r"/livetv/sessions/[0-9a-f-]{8,}"), "/livetv/sessions/{session}"),
    (re.compile(r"/[0-9a-f]{8}-[0-9a-f-]{20,}"), "/{uuid}"),
    (re.compile(r"/[0-9a-f]{12,}(-com-[\w-]+)?"), "/{client}"),
    (re.compile(r"/\d{4,}\.ts"), "/{segment}.ts"),
    (re.compile(r"/\d+"), "/{id}"),
]


NOTABLE_AT_ANY_LEVEL = re.compile(
    r"crashed|Recording failed|frames from WAL|is not writable|signal: Killed|"
    r"integrity check|Conversion failed", re.I)


def normalize_endpoint(path):
    p = path.split("?", 1)[0]
    for rx, rep in RE_ENDPOINT_ID:
        p = rx.sub(rep, p)
    return p[:110]


def source_hint(msg):
    """Which channel / session / file a transcode-side message belongs to."""
    m = re.search(r"/Grabber/([\w.-]+?)-[0-9a-f]{12,}", msg)
    if m:
        return "channel " + m.group(1)
    m = re.search(r"\[Req#[0-9a-f]+/Transcode/([0-9a-f-]{8,}?)(?:-\d+)?(?:/|\])", msg)
    if m:
        return "session " + m.group(1)[:8]
    return ""


def handle_line(a, level, ts, msg, fname, kind):
    a.levels[level] += 1
    a.level_by_kind[kind][level] += 1
    if ts:
        a.bucket[ts.replace(minute=0, second=0, microsecond=0)][level] += 1

    if level in BAD or level == "WARN":
        group = classify_group(msg)
        a.groups[group] += 1
        a.add_sig(level, msg, ts, fname, group)
        a.add_finding(msg, ts, fname, source_hint(msg))
    elif NOTABLE_AT_ANY_LEVEL.search(msg):
        # a few conditions Plex logs below WARN; cheap pre-filter keeps the hot path fast
        a.add_finding(msg, ts, fname, source_hint(msg))

    # --- HTTP ---------------------------------------------------------
    if msg.startswith("Completed: ["):
        m = RE_COMPLETED.match(msg)
        if m:
            client, status, method, path = m.groups()
            a.http_status[status] += 1
            a.http_endpoint[method + " " + normalize_endpoint(path)] += 1
            a.http_client[client.rsplit(":", 1)[0]] += 1
            if ts:
                hour = ts.replace(minute=0, second=0, microsecond=0)
                a.req_hour[hour] += 1
            ms = RE_MS.search(msg)
            by = RE_BYTES.search(msg)
            if by:
                n = int(by.group(1))
                a.http_bytes += n
                a.client_bytes[client.rsplit(":", 1)[0]] += n
                if ts:
                    a.bytes_hour[hour] += n
            if RE_TIMELINE.search(path) or "/:/timeline" in msg:
                q = dict(RE_QS.findall(msg))
                st = q.get("state")
                if st:
                    a.timeline[st] += 1
                    if ts and st == "playing":
                        a.timeline_hour[ts.replace(minute=0, second=0, microsecond=0)] += 1
                    rk = q.get("ratingKey")
                    if rk:
                        a.views[(rk, client.rsplit(":", 1)[0])].append((ts, st))
            if ms:
                v = int(ms.group(1))
                a.http_ms[v] += 1
                a.slow.append((v, method + " " + path[:120], ts, status))
                if len(a.slow) > 4000:
                    a.slow.sort(reverse=True)
                    del a.slow[500:]
        return

    if msg.startswith("Request: ["):
        m = RE_REQUEST.match(msg)
        if m:
            u = RE_USER.search(msg)
            if u:
                a.http_user[u.group(1)] += 1
        return

    # --- server identity / startup ------------------------------------
    m = RE_BANNER.match(msg)
    if m:
        a.server_info.append((ts, m.group(1), m.group(2), m.group(3), fname))
        if m.group(1) == "Media Server":
            a.opens.append((ts, m.group(2), fname))
        return
    m = RE_HOSTOS.match(msg)
    if m:
        a.server_info.append((ts, "host", m.group(2), "", fname))
        return

    # --- jobs / terminations ------------------------------------------
    if kind == "Media Server" and RE_STARTUP.search(msg):
        if not a.starts or not ts or not a.starts[-1][0] or \
                abs((ts - a.starts[-1][0]).total_seconds()) > 120:
            a.starts.append((ts, "", fname))
        return

    m = RE_JOB.match(msg)
    if m:
        binname = os.path.basename(m.group(1))
        a.jobs[(binname, m.group(4))] += 1
        if m.group(4) != "success":
            a.job_events.append((ts, binname, m.group(3), m.group(4)))
        return
    m = RE_TERM.search(msg)
    if m:
        a.terminations[m.group(1).strip()] += 1
        return

    # --- playback decisions -------------------------------------------
    if "MDE:" in msg:
        t = RE_MDE_TITLE.search(msg)
        if t and (not t.group(1).startswith("E") or " - " in t.group(1)):
            a.mde[t.group(1).strip()] += 1
        r = RE_MDE_REASON.search(msg)
        if r:
            a.mde_reason[r.group(1).strip()[:90]] += 1
        return
    if "[Now]" in msg:
        m = RE_NOW_USER.search(msg)
        if m:
            a.play_users[m.group(1)] += 1
            return
        m = RE_NOW_DEV.search(msg)
        if m:
            label = m.group(1).strip()
            if m.group(2).strip():
                label += " - " + m.group(2).strip()
            a.play_devices[label] += 1
            return
        m = RE_NOW_PROFILE.search(msg)
        if m:
            a.play_profiles[m.group(1)] += 1
        return

    m = RE_ADDED.match(msg)
    if m:
        a.item_titles[m.group(2)] = m.group(1)
        a.added_items.append((ts, m.group(1), m.group(2)))
        return

    m = RE_CHANNEL.search(msg)
    if m:
        a.channels[m.group(1)] += 1

    m = RE_BUTLER.match(msg)
    if m:
        a.butler[m.group(1)] += 1


# ---------------------------------------------------------------------------
# Transcoder Statistics (XML session reports)
# ---------------------------------------------------------------------------
import xml.etree.ElementTree as ET

STALL_MS = 8000          # a segment window this long means the source stopped feeding

RE_REPORT = re.compile(r"<SessionReport\b.*?</SessionReport>", re.S)


def parse_sessions(text, fname):
    out = []
    for block in RE_REPORT.findall(text):
        try:
            root = ET.fromstring(block)
        except ET.ParseError:
            continue
        s = dict(file=fname, start=root.get("startTimestamp", ""),
                 key=root.get("key", ""), session=root.get("session", ""),
                 transcode=root.get("transcode", ""))
        u = root.find("User")
        s["user"] = u.get("title", "") if u is not None else ""
        p = root.find("Player")
        if p is not None:
            s.update(product=p.get("product", ""), platform=p.get("platform", ""),
                     device=p.get("title") or p.get("device", ""),
                     address=p.get("remotePublicAddress") or p.get("address", ""),
                     local=p.get("local", ""), relayed=p.get("relayed", ""),
                     secure=p.get("secure", ""))
        variants = root.findall("./Variants/Variant")
        if variants:
            v = variants[0]
            s.update(video_decision=v.get("videoDecision", ""),
                     audio_decision=v.get("audioDecision", ""),
                     src_video=v.get("sourceVideoCodec", ""), dst_video=v.get("videoCodec", ""),
                     src_audio=v.get("sourceAudioCodec", ""), dst_audio=v.get("audioCodec", ""),
                     protocol=v.get("protocol", ""), container=v.get("container", ""),
                     target_bitrate=v.get("targetBitrate", ""),
                     hw_requested=v.get("transcodeHwRequested", ""),
                     hw_encode=v.get("transcodeHwEncodingTitle") or v.get("transcodeHwEncoding", ""),
                     hw_decode=v.get("transcodeHwDecodingTitle", ""),
                     variants=len(variants))
            media = v.find("Media")
            if media is not None:
                s.update(resolution=media.get("videoResolution", ""),
                         bitrate=media.get("bitrate", ""), origin=media.get("origin", ""),
                         channel=media.get("channelCallSign", ""))
        # Each Segment's Transcode timeline is the wall-clock window in which that
        # segment was finished, and the windows tile the session end to end. So it
        # measures pacing, not encoder work: for a live source the transcoder waits
        # on the tuner, and ~1 second of wall per 1 second of media is the ceiling,
        # not a shortfall. Long windows are the source stalling.
        segs = root.findall("./SegmentList/Segment")
        media_ms = 0
        windows = []
        for seg in segs:
            try:
                media_ms += int(seg.get("duration", "0"))
            except ValueError:
                pass
            for tl in seg.findall("./Timelines/Transcode"):
                try:
                    windows.append((int(tl.get("startTime", "0")),
                                    int(tl.get("endTime", "0"))))
                except ValueError:
                    pass
        widths = sorted(e - st for st, e in windows if e >= st)
        span = (max(e for _, e in windows) - min(st for st, _ in windows)) if windows else 0
        stalls = [(st, e - st) for st, e in windows if e - st > STALL_MS]
        s.update(segments=len(segs), media_ms=media_ms, span_ms=span,
                 median_window=(widths[len(widths) // 2] if widths else None),
                 p90_window=(widths[int(len(widths) * .9)] if widths else None),
                 stalls=len(stalls), stall_ms=sum(d for _, d in stalls),
                 live=(root.get("key", "").startswith("/livetv")
                       or s.get("origin") == "livetv"))
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------
def ingest(paths, since=None, top=40):
    a = Agg(top=top)
    for name, src in sorted(iter_sources(paths), key=lambda x: rotation_key(x[0])):
        kind = classify_file(name)
        try:
            text = read_text(src)
        except Exception as exc:
            a.files.append(dict(name=name, kind=kind, lines=0, parsed=0, fmt="unreadable",
                                first=None, last=None, note=str(exc)[:120]))
            continue

        if kind == "Transcoder session reports":
            found = parse_sessions(text, name)
            a.sessions.extend(found)
            for sess in found:
                if sess.get("stalls"):
                    rec = a.findings["source_stall"]
                    rec["count"] += sess["stalls"]
                    rec["files"][name] += sess["stalls"]
                    rec["sources"][(sess.get("channel") or sess.get("product")
                                    or "session " + sess.get("transcode", "")[:8])] += sess["stalls"]
                    if len(rec["samples"]) < a.nsamples:
                        rec["samples"].append(
                            (None, "session started %s: %d segment(s) took over %ds to fill, "
                                   "%.0fs of the session with nothing arriving"
                             % (sess.get("start", "?"), sess["stalls"], STALL_MS // 1000,
                                sess["stall_ms"] / 1000.0)))
            a.files.append(dict(name=name, kind=kind, lines=text.count("\n") + 1,
                                parsed=len(found), fmt="xml session report",
                                first=None, last=None,
                                note="%d session report(s)" % len(found)))
            continue

        lines = text.splitlines()
        fmt_name, rx, tsfmts = detect_format(lines)
        nparsed = 0
        fmin = fmax = None
        prev_ok = False
        for line in lines:
            if not line.strip():
                continue
            a.total_lines += 1
            m = rx.match(line) if rx else None
            if not m:
                if prev_ok:                        # continuation of a multi-line message
                    a.continuation_lines += 1
                    continue
                a.unparsed_lines += 1
                shape = signature(line.strip())[:120]
                if shape in a.unmatched_shape or len(a.unmatched_shape) < 5000:
                    a.unmatched_shape[shape] += 1
                continue
            prev_ok = True
            nparsed += 1
            ts = parse_ts(m.group("ts"), tsfmts)
            if since and ts and ts < since:
                continue
            level = norm_level(m.group("level"))
            msg = m.group("msg")
            a.note_time(ts, core=(kind == "Media Server"))
            if ts:
                fmin = ts if fmin is None or ts < fmin else fmin
                fmax = ts if fmax is None or ts > fmax else fmax
            handle_line(a, level, ts, msg, name, kind)
            if kind.startswith("Scanner") and RE_SCAN_CMD.search(msg):
                a.scans.append((ts, RE_SCAN_CMD.search(msg).group(1)[:160], name))

        a.files.append(dict(name=name, kind=kind, lines=len([l for l in lines if l.strip()]),
                            parsed=nparsed, fmt=fmt_name, first=fmin, last=fmax, note=""))
    return a


def viewing_sessions(a, gap_minutes=15):
    """Group /:/timeline events into sessions. A gap longer than gap_minutes
    between events from the same item and client starts a new one."""
    out = []
    for (rk, client), evs in a.views.items():
        evs = sorted([e for e in evs if e[0]])
        if not evs:
            continue
        cur = [evs[0]]
        for ev in evs[1:]:
            if (ev[0] - cur[-1][0]).total_seconds() > gap_minutes * 60:
                out.append((rk, client, cur))
                cur = [ev]
            else:
                cur.append(ev)
        out.append((rk, client, cur))
    sessions = []
    for rk, client, evs in out:
        states = Counter(s for _, s in evs)
        sessions.append(dict(
            rating_key=rk, client=client,
            title=a.item_titles.get(rk, "item " + rk),
            start=evs[0][0], end=evs[-1][0],
            seconds=(evs[-1][0] - evs[0][0]).total_seconds(),
            events=len(evs), buffering=states.get("buffering", 0),
            paused=states.get("paused", 0), stopped=states.get("stopped", 0)))
    sessions.sort(key=lambda s: s["start"])
    return sessions


def detect_format(lines, probe=400):
    """Pick the format that matches the most of the first N non-blank lines."""
    sample = [l for l in lines[:probe * 3] if l.strip()][:probe]
    best = (0, "unrecognised", None, ())
    for name, rx, fmts in FORMATS:
        hits = sum(1 for l in sample if rx.match(l))
        if hits > best[0]:
            best = (hits, name, rx, fmts)
    if best[0] == 0:
        return "unrecognised", None, ()
    return best[1], best[2], best[3]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Context"}

CSS = """
:root{
  --paper:#fdfdfc; --panel:#f4f3f0; --ink:#17191b; --dim:#5f656c; --line:#e2dfda;
  --crit:#8f1219; --high:#a2560f; --med:#7a6a14; --low:#47586a; --info:#5a636b; --ok:#1d6a49;
  --accent:#1f3d5c;
}
@media (prefers-color-scheme:dark){
  :root{--paper:#16181a; --panel:#1e2124; --ink:#e8e6e2; --dim:#9aa1a8; --line:#2e3236;
        --crit:#e0575f; --high:#d99247; --med:#c9b45c; --low:#8fa6bd; --info:#93a0aa;
        --ok:#5fbd8f; --accent:#9dc0e0;}
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px 80px}
@media (min-width:900px){
  .wrap{display:grid;grid-template-columns:186px minmax(0,1fr);gap:52px;padding:44px 32px 100px}
  nav{position:sticky;top:32px;align-self:start;font-size:13.5px;line-height:1.9;
      max-height:calc(100vh - 64px);overflow:auto}
  nav a{display:block;color:var(--dim);text-decoration:none;padding:1px 0 1px 12px;
        border-left:2px solid transparent}
  nav a:hover{color:var(--ink);border-left-color:var(--accent)}
}
@media (max-width:899px){
  nav{position:sticky;top:0;z-index:20;background:var(--paper);margin:0 -20px;padding:10px 20px;
      border-bottom:1px solid var(--line);white-space:nowrap;overflow-x:auto;
      -webkit-overflow-scrolling:touch;font-size:13px}
  nav a{display:inline-block;color:var(--dim);text-decoration:none;padding:5px 11px;margin-right:6px;
        border:1px solid var(--line);border-radius:999px}
  header.top{padding-top:26px}
}
header.top{padding-top:8px}
h1{font-size:clamp(25px,6vw,34px);line-height:1.12;margin:14px 0 8px;letter-spacing:-.021em;font-weight:660}
h2{font-size:clamp(19px,4.4vw,22px);margin:56px 0 6px;letter-spacing:-.012em;font-weight:650;
  padding-top:18px;border-top:1px solid var(--line)}
h3{font-size:16px;margin:30px 0 4px;font-weight:640;letter-spacing:-.005em}
p,li{max-width:70ch}
.lede{color:var(--dim);margin:0 0 6px;font-size:15.5px}
.sub{color:var(--dim);font-size:13.5px;margin:8px 0 0}
.facts{border:1px solid var(--line);border-radius:6px;overflow:hidden;margin:26px 0 10px;
  font-size:0}
.fact{display:inline-block;vertical-align:top;width:50%;font-size:15px;
  padding:14px 16px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
@supports (display:grid){
  .facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
  .fact{display:block;width:auto}
}
.fact b{display:block;font:640 22px/1.15 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.fact span{display:block;color:var(--dim);font-size:12.5px;margin-top:4px;line-height:1.35}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:14px 0 4px}
table{border-collapse:collapse;width:100%;font-size:14px;min-width:min(560px,100%)}
th{text-align:left;font-weight:600;color:var(--dim);border-bottom:1px solid var(--line);
  padding:7px 14px 7px 0;font-size:12.5px;white-space:nowrap}
td{padding:8px 14px 8px 0;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.n,th.n{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums;white-space:nowrap;padding-right:0}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--panel);padding:12px 14px;overflow-x:auto;font-size:12px;line-height:1.55;
  margin:10px 0;white-space:pre-wrap;word-break:break-word;border-radius:5px;
  border-left:2px solid var(--line)}
.find{border-left:3px solid var(--line);padding:2px 0 6px 18px;margin:26px 0;break-inside:avoid}
.find.critical{border-left-color:var(--crit)} .find.high{border-left-color:var(--high)}
.find.medium{border-left-color:var(--med)} .find.low{border-left-color:var(--low)}
.find.info{border-left-color:var(--info)}
.find h3{margin-top:0}
.find h3 .sev{margin-right:10px} .find h3 .meta{margin-left:8px;font-weight:400}
.sev{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;padding:2px 8px;
  border-radius:3px;color:#fff;vertical-align:2px}
@media (prefers-color-scheme:dark){.sev{color:#16181a}}
.sev.critical{background:var(--crit)} .sev.high{background:var(--high)}
.sev.medium{background:var(--med)} .sev.low{background:var(--low)} .sev.info{background:var(--info)}
.meta{color:var(--dim);font-size:12.5px;margin:2px 0 10px}
.find p{margin:8px 0}
.check{background:var(--panel);padding:11px 14px;margin:12px 0 4px;font-size:14px;border-radius:5px}
details{margin:10px 0}
summary{cursor:pointer;color:var(--dim);font-size:13.5px;padding:3px 0}
summary:hover{color:var(--ink)}
.band{width:100%;height:132px;display:block;margin:12px 0 2px}
@media (min-width:900px){.band{height:150px}}
.cap{display:flex;justify-content:space-between;gap:12px;color:var(--dim);
  font-size:12px;margin:0 0 6px;font-variant-numeric:tabular-nums}
.legend{color:var(--dim);font-size:13px;margin:2px 0 0}
.bar{display:inline-block;height:8px;background:var(--dim);opacity:.45;vertical-align:middle;
  border-radius:2px;min-width:2px}
.bar.err{background:var(--crit);opacity:.85}
input[type=search]{width:100%;max-width:440px;padding:9px 12px;border:1px solid var(--line);
  border-radius:6px;font:14px inherit;margin:12px 0 2px;background:var(--paper);color:var(--ink)}
.tag{display:inline-block;font-size:11.5px;color:var(--dim);border:1px solid var(--line);
  border-radius:3px;padding:1px 7px;margin:0 5px 3px 0;white-space:nowrap}
.empty{color:var(--dim);font-style:italic}
.nw{white-space:nowrap}
footer{color:var(--dim);font-size:13px;margin-top:64px;border-top:1px solid var(--line);padding-top:16px}
@media print{
  nav{display:none} .wrap{display:block;max-width:none;padding:0}
  body{background:#fff;color:#000;font-size:10.5pt}
  h2{break-after:avoid} .find{break-inside:avoid} pre{white-space:pre-wrap}
  details>summary{display:none} details>pre{display:block} a{color:inherit;text-decoration:none}
}
"""

JS = """
(function(){
  var box=document.getElementById('sigfilter');
  if(!box) return;
  box.addEventListener('input',function(){
    var q=this.value.toLowerCase();
    document.querySelectorAll('#sigtable tbody tr').forEach(function(tr){
      tr.style.display = tr.textContent.toLowerCase().indexOf(q)>-1 ? '' : 'none';
    });
  });
})();
"""


def esc(s):
    return html.escape(str(s), quote=False)


def ts_str(t, fmt="%b %d %H:%M:%S"):
    return t.strftime(fmt) if t else "-"


def num(n):
    return "{:,}".format(n)


def dur(td):
    if not td:
        return "-"
    s = int(td.total_seconds())
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


def rows(pairs, headers, widths=None, limit=None):
    """pairs: list of tuples already stringified; last column right-aligned if numeric."""
    out = ["<div class=scroll><table><thead><tr>"]
    for i, h in enumerate(headers):
        cls = ' class="n"' if h.startswith("#") else ""
        out.append("<th%s>%s</th>" % (cls, esc(h.lstrip("#"))))
    out.append("</tr></thead><tbody>")
    for r in (pairs[:limit] if limit else pairs):
        out.append("<tr>")
        for i, cell in enumerate(r):
            cls = ' class="n"' if headers[i].startswith("#") else ""
            out.append("<td%s>%s</td>" % (cls, cell))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def activity_band(a, lo=None, hi=None):
    """Hour-by-hour volume with the error share drawn inside each column."""
    if not a.bucket:
        return ""
    hours = sorted(a.bucket)
    if lo and hi:
        hours = [h for h in hours if lo - timedelta(hours=1) <= h <= hi + timedelta(hours=1)]
        if not hours:
            hours = sorted(a.bucket)
    lo, hi = hours[0], hours[-1]
    span = int((hi - lo).total_seconds() // 3600) + 1
    if span > 24 * 21:
        return ""
    cols = [lo + timedelta(hours=i) for i in range(span)]
    tot = [sum(a.bucket.get(c, Counter()).values()) for c in cols]
    err = [sum(v for k, v in a.bucket.get(c, Counter()).items() if k in BAD) for c in cols]
    peak = max(tot) or 1
    W, H = 1000, 110
    cw = W / max(len(cols), 1)
    bw = max(cw - 1.4, 1.2)
    parts = ['<svg class="band" viewBox="0 0 %d %d" preserveAspectRatio="none" '
             'xmlns="http://www.w3.org/2000/svg" role="img" '
             'aria-label="log lines per hour">' % (W, H)]
    for i, c in enumerate(cols):
        h = ((tot[i] / peak) ** 0.5) * H
        eh = h * (err[i] / tot[i]) if tot[i] else 0
        x = i * cw
        if h > 0:
            parts.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="#c9c6c0"><title>%s  %s lines, %s errors</title></rect>'
                         % (x, H - h, bw, h, c.strftime("%a %d %H:00"), num(tot[i]), num(err[i])))
        if eh > 0:
            parts.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="#8f1219"/>'
                         % (x, H - eh, bw, eh))
        if c.hour == 0 and i:
            parts.append('<line x1="%.2f" y1="0" x2="%.2f" y2="%d" stroke="#9aa1a8" '
                         'stroke-opacity=".35"/>' % (x, x, H))
    parts.append('<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#9aa1a8" stroke-opacity=".35"/>'
                 % (H, W, H))
    parts.append("</svg>")
    parts.append('<p class=cap><span>%s</span><span>busiest hour %s lines, %s errors</span>'
                 '<span>%s</span></p>'
                 % (cols[0].strftime("%a %d %b %H:00"), num(peak),
                    num(max(err) if err else 0), cols[-1].strftime("%a %d %b %H:00")))
    return "".join(parts)


def hourly_chart(counter, lo, hi, fill="#7a8794", fmt=lambda v: num(v), label="per hour"):
    if not counter or not lo or not hi:
        return ""
    span = int((hi - lo).total_seconds() // 3600) + 1
    if span < 1 or span > 24 * 31:
        return ""
    cols = [lo.replace(minute=0, second=0, microsecond=0) + timedelta(hours=i) for i in range(span)]
    vals = [counter.get(c, 0) for c in cols]
    peak = max(vals) or 1
    W, H = 1000, 100
    cw = W / max(len(cols), 1)
    bw = max(cw - 1.6, 1.2)
    out = ['<svg class="band" viewBox="0 0 %d %d" preserveAspectRatio="none" '
           'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="%s">' % (W, H, label)]
    for i, c in enumerate(cols):
        h = (vals[i] / peak) * H
        x = i * cw
        if h > 0:
            out.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" rx="1">'
                       '<title>%s  %s</title></rect>'
                       % (x, H - h, bw, h, fill, c.strftime("%a %d %H:00"), fmt(vals[i])))
        if c.hour == 0 and i:
            out.append('<line x1="%.2f" y1="0" x2="%.2f" y2="%d" stroke="#9aa1a8" '
                       'stroke-opacity=".35"/>' % (x, x, H))
    out.append('<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#9aa1a8" stroke-opacity=".35"/>'
               % (H, W, H))
    out.append("</svg>")
    out.append('<p class=cap><span>%s</span><span>peak %s in one hour</span><span>%s</span></p>'
               % (cols[0].strftime("%a %d %b %H:00"), fmt(peak),
                  cols[-1].strftime("%a %d %b %H:00")))
    return "".join(out)


def render(a, opts):
    R = opts.redact
    P = []
    add = P.append

    # ---- identity -----------------------------------------------------
    ver = plat = host = ""
    for t, kind, v, extra, f in a.server_info:
        if kind == "Media Server" and not ver:
            ver, plat = v, extra
        elif kind == "host" and not host:
            host = v

    lo = a.core_min or a.tmin
    hi = a.core_max or a.tmax
    window = "-"
    if lo and hi:
        window = "%s to %s" % (lo.strftime("%b %d %H:%M"), hi.strftime("%b %d %H:%M"))
    stale = [f for f in a.files if f["last"] and lo and f["last"] < lo - timedelta(days=2)]

    decoder_errors = sum(r["count"] for r in a.sigs.values()
                         if r["level"] in BAD and r["group"] == "Transcoder decoder")
    real_errors = sum(r["count"] for r in a.sigs.values()
                      if r["level"] in BAD and r["group"] != "Transcoder decoder")
    warns = sum(r["count"] for r in a.sigs.values() if r["level"] == "WARN")

    active = sorted([r for r in a.findings.values() if r["count"]],
                    key=lambda r: (SEV_ORDER[r["sev"]], -r["count"]))
    attention = [r for r in active if r["sev"] in ("critical", "high")]

    add("<!doctype html><html lang=en><head><meta charset=utf-8>")
    add('<meta name=viewport content="width=device-width,initial-scale=1">')
    add("<title>Plex log report %s</title><style>%s</style></head><body><div class=wrap>"
        % (esc(window), CSS))

    nav = [("Summary", "top"), ("What needs attention", "findings"), ("Activity", "activity"),
           ("Statistics", "stats"), ("Playback", "playback"), ("Requests", "http"), ("Errors and warnings", "errors"),
           ("Maintenance", "maint"), ("Library scans", "scans"), ("Files read", "files"),
           ("Coverage", "coverage")]
    add("<nav>" + "".join('<a href="#%s">%s</a>' % (i, esc(n)) for n, i in nav) + "</nav>")
    add("<main id=top>")

    # ---- header -------------------------------------------------------
    add('<header class=top>')
    add("<h1>Plex server log report</h1>")
    bits = []
    if ver:
        bits.append("Plex Media Server " + esc(ver))
    if plat:
        bits.append(esc(plat.split(" - build")[0]))
    if host:
        bits.append(esc(host))
    add('<p class="lede">%s<br>Covering %s (%s of log time), from %d files.</p>'
        % (", ".join(bits) if bits else "server version not found in these logs",
           esc(window), dur(hi - lo) if lo and hi else "-", len(a.files)))
    if stale:
        add('<p class=sub>%d of those files were last written before this window and are kept '
            'here only as old rotations; they are listed under Files read.</p>' % len(stale))

    add('</header>')
    verdict = ("%d thing%s worth looking at" % (len(attention), "" if len(attention) == 1 else "s")
               if attention else "nothing at critical or high severity")
    add('<div class=facts>')
    add('<div class=fact><b>%s</b><span>%s</span></div>'
        % (num(len(attention)) if attention else "0",
           "issues at critical or high" if attention else "critical or high issues"))
    add('<div class=fact><b>%s</b><span>errors, excluding decoder chatter</span></div>' % num(real_errors))
    add('<div class=fact><b>%s</b><span>decoder errors from transcoding</span></div>' % num(decoder_errors))
    add('<div class=fact><b>%s</b><span>warnings</span></div>' % num(warns))
    add('<div class=fact><b>%s</b><span>lines read</span></div>' % num(a.total_lines))
    add('</div>')
    add('<p class=sub>%s. Every number below is a count of log lines; nothing is estimated.</p>'
        % verdict.capitalize())

    # ---- findings -----------------------------------------------------
    add('<h2 id=findings>What needs attention</h2>')
    if not active:
        add('<p class=empty>No rule in the findings table matched any line in these logs.</p>')
    for r in active:
        add('<div class="find %s">' % r["sev"])
        add('<h3><span class="sev %s">%s</span> %s <span class=meta>%s occurrence%s</span></h3>'
            % (r["sev"], SEV_LABEL[r["sev"]], esc(r["title"]), num(r["count"]),
               "" if r["count"] == 1 else "s"))
        span = "first %s, last %s" % (ts_str(r["first"]), ts_str(r["last"]))
        files = ", ".join("%s (%s)" % (esc(os.path.basename(f)), num(c))
                          for f, c in r["files"].most_common(3))
        add('<p class=meta>%s &nbsp; in %s</p>' % (span, files))
        add("<p>%s</p>" % esc(r["meaning"]))
        if r["sources"]:
            top = ", ".join("%s (%s)" % (esc(s), num(c)) for s, c in r["sources"].most_common(6))
            add('<p class=meta>Concentrated in: %s</p>' % top)
        add('<div class=check><b>Worth checking:</b> %s</div>' % esc(r["check"]))
        if r["samples"]:
            add("<details><summary>Sample lines</summary><pre>%s</pre></details>"
                % esc("\n".join("%s  %s" % (ts_str(t, "%b %d %H:%M:%S"), scrub(m, R))
                                for t, m in r["samples"])))
        add("</div>")

    # ---- activity -----------------------------------------------------
    add('<h2 id=activity>Activity</h2>')
    band = activity_band(a, lo, hi)
    if band:
        add('<p class=legend>Log lines per hour, on a square-root scale so quiet hours stay '
            'visible. The dark part of each column is the share that was errors.</p>')
        add(band)
    lv = [(esc(k), num(v), '<span class="bar%s" style="width:%dpx"></span>'
           % (" err" if k in BAD else "",
              max(1, int(220 * (v / max(a.levels.values())) ** 0.5))))
          for k, v in sorted(a.levels.items(), key=lambda kv: LEVELS.index(kv[0]))]
    add(rows(lv, ["Level", "#Lines", ""]))
    if a.starts or a.opens:
        add("<h3>Server starts</h3>")
        if a.starts:
            add(rows([(ts_str(t, "%b %d %H:%M:%S"), esc(os.path.basename(f)))
                      for t, v, f in a.starts], ["Time", "Seen in"]))
        else:
            add('<p class=empty>No startup sequence in this window - the server was already '
                'running when the oldest of these logs begins.</p>')
        add('<p class=sub>Counted from the startup sequence itself (database sessions opening, '
            'HTTP listener binding), not from the version banner: Plex reprints that banner at '
            'the top of every rotated log, and it opened %d log file%s in this window.</p>'
            % (len(a.opens), "" if len(a.opens) == 1 else "s"))

    # ---- statistics ---------------------------------------------------
    add('<h2 id=stats>Statistics</h2>')
    vs = viewing_sessions(a)
    watch_s = sum(v["seconds"] for v in vs)
    buffering = sum(v["buffering"] for v in vs)
    tc_media = sum(s.get("media_ms", 0) for s in a.sessions if s.get("live") is not False) / 1000.0
    timed = sum(a.http_ms.values())

    add('<div class=facts>')
    add('<div class=fact><b>%s</b><span>watched, across %d session%s</span></div>'
        % (dur_secs(watch_s), len(vs), "" if len(vs) == 1 else "s"))
    add('<div class=fact><b>%s</b><span>transcoded media produced</span></div>' % dur_secs(tc_media))
    add('<div class=fact><b>%s</b><span>served over HTTP</span></div>' % human_bytes(a.http_bytes))
    add('<div class=fact><b>%s</b><span>completed requests</span></div>'
        % num(sum(a.http_status.values())))
    add('<div class=fact><b>%s</b><span>buffering events reported by clients</span></div>'
        % num(a.timeline.get("buffering", buffering)))
    add('<div class=fact><b>%s</b><span>items added to the library</span></div>'
        % num(len(a.added_items)))
    add('</div>')

    if a.bytes_hour:
        add("<h3>Data served per hour</h3>")
        add(hourly_chart(a.bytes_hour, lo, hi, "#3f6f96", human_bytes, "bytes per hour"))
    if a.req_hour:
        add("<h3>Requests per hour</h3>")
        add(hourly_chart(a.req_hour, lo, hi, "#7a8794", num, "requests per hour"))
    if timed:
        add("<h3>Response times</h3>")
        add(rows([("Median", "%s ms" % num(percentile(a.http_ms, .5))),
                  ("75th percentile", "%s ms" % num(percentile(a.http_ms, .75))),
                  ("90th percentile", "%s ms" % num(percentile(a.http_ms, .90))),
                  ("99th percentile", "%s ms" % num(percentile(a.http_ms, .99))),
                  ("Longest", "%s ms" % num(max(a.http_ms)))],
                 ["Across %s timed requests" % num(timed), "#Duration"]))
        add('<p class=sub>The long tail is streaming and file downloads, which stay open while '
            'the client reads from them.</p>')

    if vs:
        add("<h3>Viewing sessions</h3>")
        vrows = []
        for v in sorted(vs, key=lambda v: -v["seconds"])[:25]:
            flags = []
            if v["buffering"]:
                flags.append("%d buffering" % v["buffering"])
            if v["paused"]:
                flags.append("%d paused" % v["paused"])
            vrows.append((esc(v["title"]), esc(mask_ip(v["client"]) if R else v["client"]),
                          '<span class=nw>%s</span>' % ts_str(v["start"], "%b %d %H:%M"),
                          dur_secs(v["seconds"]),
                          ", ".join(esc(f) for f in flags) or "clean", num(v["events"])))
        add(rows(vrows, ["What", "Client", "Started", "#Length", "Playback", "#Events"]))
        add('<p class=sub>Rebuilt from the timeline updates clients post while playing, grouped '
            'into a session when the gaps are under 15 minutes. Length is wall-clock between the '
            'first and last update, so a paused stream still counts.</p>')
    if a.timeline:
        add(rows([(esc(k), num(v)) for k, v in a.timeline.most_common()],
                 ["Playback state reported", "#Updates"]))
    if a.channels:
        add("<h3>Live TV sources</h3>")
        add(rows([(esc(k), num(v)) for k, v in a.channels.most_common(12)],
                 ["Tuner channel stream", "#Log lines"]))
    if a.client_bytes:
        add("<h3>Data by client</h3>")
        add(rows([(esc(mask_ip(k) if R else k), human_bytes(v), num(a.http_client.get(k, 0)))
                  for k, v in a.client_bytes.most_common(10)],
                 ["Client", "#Served", "#Requests"]))
    if a.added_items:
        add("<h3>Added to the library</h3>")
        add(rows([('<span class=nw>%s</span>' % ts_str(t, "%b %d %H:%M"), esc(title), esc(mid))
                  for t, title, mid in a.added_items[-15:]], ["When", "Title", "#ID"]))

    # ---- playback -----------------------------------------------------
    add('<h2 id=playback>Playback</h2>')
    if a.sessions:
        add("<h3>Transcode session reports</h3>")
        tbl = []
        for s in sorted(a.sessions, key=lambda s: s.get("start", "")):
            who = s.get("user") or "server side"
            if R:
                who = "<user>"
            dev = " ".join(x for x in (s.get("product", ""), s.get("device", "")) if x)[:46]
            dec = "%s video / %s audio" % (s.get("video_decision", "?"), s.get("audio_decision", "?"))
            path = "%s to %s" % (s.get("src_video", "?"), s.get("dst_video", "?"))
            hw = s.get("hw_encode") or ("requested" if s.get("hw_requested") == "1" else "software")
            where = "local" if s.get("local") == "1" else ("relayed" if s.get("relayed") == "1" else "remote")
            mw = s.get("median_window")
            if s.get("stalls"):
                pacing = ("%d stall%s, %s lost" %
                          (s["stalls"], "" if s["stalls"] == 1 else "s",
                           dur_secs(s["stall_ms"] / 1000.0)))
            elif mw:
                pacing = "steady, %.2f s per second of media" % (mw / 1000.0)
            else:
                pacing = "-"
            extra = []
            if s.get("channel"):
                extra.append(esc(s["channel"]))
            if s.get("resolution"):
                extra.append(esc(s["resolution"]))
            if s.get("origin"):
                extra.append(esc(s["origin"]))
            tbl.append((esc(s.get("start", "")[:20]), esc(who), esc(dev),
                        esc(dec) + "<br><span class=meta>" + esc(path) + ", " + esc(hw) + "</span>",
                        " ".join('<span class=tag>%s</span>' % e for e in extra),
                        esc(where), num(s.get("segments", 0)), esc(pacing)))
        add(rows(tbl, ["Started", "User", "Client", "Decision", "Source", "Link",
                       "#Segments", "Pacing"]))
        add('<p class=sub>Pacing comes from the segment timelines, which record the wall-clock '
            'window each segment was finished in. A live source arrives in real time, so about '
            'one second of wall per second of media is the ceiling and means the transcoder '
            'never fell behind. Windows far longer than a segment mean the source stopped '
            'feeding, not that the encoder was slow.</p>')
    else:
        add('<p class=empty>No transcoder session reports in this set.</p>')

    if a.play_users or a.play_devices:
        add("<h3>Who and what was playing</h3>")
        u = [(("&lt;user&gt;" if R else esc(k)), num(v)) for k, v in a.play_users.most_common(10)]
        d = [(esc(k), num(v)) for k, v in a.play_devices.most_common(10)]
        add(rows(u, ["Account seen in play state updates", "#Lines"]))
        add(rows(d, ["Client device", "#Lines"]))
    if a.mde:
        add("<h3>Titles Plex made a playback decision for</h3>")
        add(rows([(esc(k), num(v)) for k, v in a.mde.most_common(20)],
                 ["Title", "#Decisions"]))
    if a.mde_reason:
        add("<h3>Why it transcoded</h3>")
        add(rows([(esc(k), num(v)) for k, v in a.mde_reason.most_common(12)],
                 ["Reason given", "#Times"]))
    if a.terminations:
        add("<h3>How sessions ended</h3>")
        add(rows([(esc(k), num(v)) for k, v in a.terminations.most_common(12)],
                 ["Reason", "#Sessions"]))

    # ---- http ---------------------------------------------------------
    add('<h2 id=http>Requests</h2>')
    if a.http_status:
        total = sum(a.http_status.values())
        med = percentile(a.http_ms, .5)
        p95 = percentile(a.http_ms, .95)
        add('<div class=facts>'
            '<div class=fact><b>%s</b><span>completed requests</span></div>'
            '<div class=fact><b>%s</b><span>median response</span></div>'
            '<div class=fact><b>%s</b><span>95th percentile</span></div>'
            '<div class=fact><b>%s</b><span>served</span></div></div>'
            % (num(total), "%d ms" % med, "%d ms" % p95, human_bytes(a.http_bytes)))
        bad_status = [(k, v) for k, v in a.http_status.items() if k[0] in "45"]
        add(rows([(esc(k), num(v), "%.1f%%" % (100.0 * v / total))
                  for k, v in sorted(a.http_status.items())],
                 ["Status", "#Count", "#Share"]))
        if bad_status:
            add('<p class=sub>%s failed request%s (4xx/5xx). 401s are normal when a client '
                'connects before presenting a token.</p>'
                % (num(sum(v for _, v in bad_status)),
                   "" if sum(v for _, v in bad_status) == 1 else "s"))
        add("<h3>Busiest endpoints</h3>")
        add(rows([(esc(k), num(v)) for k, v in a.http_endpoint.most_common(15)],
                 ["Endpoint", "#Requests"]))
        add("<h3>Clients by request volume</h3>")
        add(rows([(esc(mask_ip(k) if R else k), num(v)) for k, v in a.http_client.most_common(10)],
                 ["Client address", "#Requests"]))
        if a.http_user:
            add(rows([(("&lt;user&gt;" if R else esc(k)), num(v))
                      for k, v in a.http_user.most_common(10)],
                     ["Signed-in account on requests", "#Requests"]))
        a.slow.sort(reverse=True)
        add("<h3>Slowest completed requests</h3>")
        add(rows([("%.1f s" % (v / 1000.0), esc(scrub(p, R)), ts_str(t), esc(st))
                  for v, p, t, st in a.slow[:12]],
                 ["Duration", "Request", "When", "Status"]))
        add('<p class=sub>Streaming and download requests stay open for as long as the client '
            'reads from them, so a long duration here is not by itself a fault.</p>')
    else:
        add('<p class=empty>No completed-request lines in this set. Plex logs these at DEBUG '
            'level, so this section fills in only when debug logging is on.</p>')

    # ---- errors -------------------------------------------------------
    add('<h2 id=errors>Errors and warnings</h2>')
    sigs = sorted([r for r in a.sigs.values()], key=lambda r: -r["count"])
    if sigs:
        gcount = Counter()
        for r in sigs:
            gcount[r["group"]] += r["count"]
        add(rows([(esc(k), num(v)) for k, v in gcount.most_common()],
                 ["Area", "#Lines"]))
        add('<input type=search id=sigfilter placeholder="Filter these messages">')
        main_sigs = [r for r in sigs if r["group"] != "Transcoder decoder"]
        noise_sigs = [r for r in sigs if r["group"] == "Transcoder decoder"]
        body = []
        for r in main_sigs[:opts.top]:
            samp = "\n".join("%s  %s" % (ts_str(t, "%b %d %H:%M:%S"), scrub(m, R))
                             for t, m in r["samples"])
            body.append((
                '<span class="sev %s">%s</span>' % (
                    "critical" if r["level"] in BAD else "medium", esc(r["level"])),
                '<span class=mono>%s</span><details><summary>samples</summary><pre>%s</pre></details>'
                % (esc(scrub(r["sig"], R)), esc(samp)),
                esc(r["group"]),
                '<span class=nw>%s</span>' % ts_str(r["first"], "%b %d %H:%M"),
                '<span class=nw>%s</span>' % ts_str(r["last"], "%b %d %H:%M"),
                num(r["count"])))
        add('<div id=sigtable>' + rows(body, ["Level", "Message pattern", "Area",
                                              "First", "Last", "#Count"]) + "</div>")
        add('<p class=sub>Numbers, hex addresses and IDs are collapsed so repeats of the same '
            'message group together. Showing the top %d of %d distinct patterns, decoder '
            'chatter excluded.</p>' % (min(opts.top, len(main_sigs)), len(main_sigs)))
        if noise_sigs:
            nrows = [(esc(scrub(r["sig"], R)), ts_str(r["first"], "%b %d %H:%M"),
                      ts_str(r["last"], "%b %d %H:%M"), num(r["count"])) for r in noise_sigs[:30]]
            add("<details><summary>Decoder messages from inside the transcoder "
                "(%d patterns, %s lines)</summary>%s</details>"
                % (len(noise_sigs), num(sum(r["count"] for r in noise_sigs)),
                   rows(nrows, ["Message pattern", "First", "Last", "#Count"])))
    else:
        add('<p class=empty>No warnings or errors.</p>')

    # ---- maintenance --------------------------------------------------
    add('<h2 id=maint>Maintenance and background work</h2>')
    if a.butler:
        add(rows([(esc(k), num(v)) for k, v in a.butler.most_common(20)],
                 ["Butler task", "#Mentions"]))
    if a.jobs:
        add("<h3>Child processes</h3>")
        add(rows([(esc(k[0]), esc(k[1]), num(v)) for k, v in a.jobs.most_common(12)],
                 ["Process", "Outcome", "#Count"]))
    if a.job_events:
        add("<details><summary>Non-success process exits (%d)</summary><pre>%s</pre></details>"
            % (len(a.job_events),
               esc("\n".join("%s  %s  code %s (%s)" % (ts_str(t), b, c, k)
                             for t, b, c, k in a.job_events[:40]))))
    if not (a.butler or a.jobs):
        add('<p class=empty>No maintenance lines matched.</p>')

    # ---- scans --------------------------------------------------------
    add('<h2 id=scans>Library scans</h2>')
    if a.scans:
        add(rows([(ts_str(t, "%b %d %H:%M:%S"), '<span class=mono>%s</span>' % esc(cmd),
                   esc(os.path.basename(f))) for t, cmd, f in sorted(
                      a.scans, key=lambda s: (s[0] or datetime.min))][-25:],
                 ["When", "Scanner invocation", "Log"]))
        add('<p class=sub>Each line is one scanner process and the arguments it ran with.</p>')
    else:
        add('<p class=empty>No scanner invocations in this set.</p>')

    # ---- files --------------------------------------------------------
    add('<h2 id=files>Files read</h2>')
    frows = []
    for f in sorted(a.files, key=lambda f: (f["kind"], f["name"])):
        parsed_pct = (100.0 * f["parsed"] / f["lines"]) if f["lines"] else 0
        span = "%s to %s" % (ts_str(f["first"], "%b %d %H:%M"), ts_str(f["last"], "%b %d %H:%M")) \
            if f["first"] else (f["note"] or "-")
        frows.append((esc(f["name"]), esc(f["kind"]), esc(f["fmt"]),
                      num(f["lines"]), "%.0f%%" % parsed_pct, esc(span)))
    add(rows(frows, ["File", "Type", "Format matched", "#Lines", "#Parsed", "Time span"]))

    # ---- coverage -----------------------------------------------------
    add('<h2 id=coverage>Coverage</h2>')
    quiet = [r["title"] for r in a.findings.values() if not r["count"]]
    add("<p>%d of %d findings rules matched something. These did not fire, so nothing in "
        "these logs looked like them:</p>" % (len(active), len(a.findings)))
    add("<ul>" + "".join("<li>%s</li>" % esc(t) for t in quiet) + "</ul>" if quiet
        else "<p class=empty>Every rule fired.</p>")
    add("<p>%s of %s lines carried a timestamp and level and were parsed. %s further lines "
        "followed a parsed line without a header of their own and were treated as continuations "
        "of it, which is what stack traces look like. %s lines matched no format at all."
        % (num(a.total_lines - a.unparsed_lines - a.continuation_lines), num(a.total_lines),
           num(a.continuation_lines), num(a.unparsed_lines)))
    if a.unmatched_shape:
        add("</p><details><summary>Most common unparsed line shapes</summary><pre>%s</pre></details>"
            % esc("\n".join("%6d  %s" % (c, s) for s, c in a.unmatched_shape.most_common(25))))
    else:
        add(" Nothing was skipped.</p>")

    add('<footer>Generated by plexreport.py %s on %s. '
        'Tokens are masked in every sample line. %s</footer>'
        % (VERSION, datetime.now().strftime("%Y-%m-%d %H:%M"),
           "IP addresses, accounts and email addresses are masked (--redact)." if R
           else "Run with --redact to also mask IP addresses, accounts and email addresses."))
    add("</main></div><script>%s</script></body></html>" % JS)
    return "".join(P)


def dur_secs(sec):
    sec = int(round(sec))
    if sec >= 3600:
        return "%dh %dm" % (sec // 3600, (sec % 3600) // 60)
    if sec >= 90:
        return "%dm %ds" % (sec // 60, sec % 60)
    return "%ds" % sec


def percentile(counter, p):
    """Nearest-rank percentile (p in 0..1) over a Counter of value -> occurrences."""
    total = sum(counter.values())
    if not total:
        return 0
    target = min(int(total * p), total - 1)
    seen = 0
    for v in sorted(counter):
        seen += counter[v]
        if seen > target:
            return v
    return v


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


# ---------------------------------------------------------------------------
# JSON summary (for scripting / trending between runs)
# ---------------------------------------------------------------------------
def to_json(a):
    return dict(
        generated=datetime.now().isoformat(timespec="seconds"),
        window=dict(start=a.tmin.isoformat() if a.tmin else None,
                    end=a.tmax.isoformat() if a.tmax else None),
        lines=a.total_lines, unparsed=a.unparsed_lines,
        levels=dict(a.levels),
        findings=[dict(id=r["id"], severity=r["sev"], title=r["title"], count=r["count"],
                       first=r["first"].isoformat() if r["first"] else None,
                       last=r["last"].isoformat() if r["last"] else None)
                  for r in sorted(a.findings.values(), key=lambda r: SEV_ORDER[r["sev"]])
                  if r["count"]],
        http=dict(status=dict(a.http_status), bytes=a.http_bytes,
                  endpoints=a.http_endpoint.most_common(25)),
        sessions=[{k: v for k, v in s.items() if k != "file"} for s in a.sessions],
        top_messages=[dict(level=r["level"], group=r["group"], count=r["count"], pattern=r["sig"])
                      for r in sorted(a.sigs.values(), key=lambda r: -r["count"])[:60]],
        files=[dict(name=f["name"], kind=f["kind"], format=f["fmt"], lines=f["lines"],
                    parsed=f["parsed"]) for f in a.files],
    )


# ---------------------------------------------------------------------------
# PDF (optional; HTML is the primary output)
# ---------------------------------------------------------------------------
def write_pdf(html_path, pdf_path):
    import shutil
    import subprocess
    try:
        from weasyprint import HTML as WeasyHTML
        WeasyHTML(filename=html_path).write_pdf(pdf_path)
        return "weasyprint"
    except Exception:
        pass
    for exe, args in (
        ("wkhtmltopdf", ["--enable-local-file-access", html_path, pdf_path]),
        ("chromium", ["--headless", "--disable-gpu", "--no-sandbox",
                      "--print-to-pdf=" + pdf_path, "file://" + os.path.abspath(html_path)]),
        ("google-chrome", ["--headless", "--disable-gpu", "--no-sandbox",
                           "--print-to-pdf=" + pdf_path, "file://" + os.path.abspath(html_path)]),
    ):
        path = shutil.which(exe)
        if path:
            try:
                subprocess.run([path] + args, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return exe
            except subprocess.CalledProcessError:
                continue
    return None


def parse_since(text):
    if not text:
        return None
    m = re.fullmatch(r"(\d+)\s*([hdw])", text.strip(), re.I)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        hours = n * {"h": 1, "d": 24, "w": 168}[unit]
        return datetime.now() - timedelta(hours=hours)
    for f in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, f)
        except ValueError:
            pass
    raise SystemExit("could not read --since %r (try 24h, 3d, 2w or 2026-09-09)" % text)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Turn Plex Media Server logs into a readable HTML report.")
    ap.add_argument("paths", nargs="+", help="log zip, Logs directory, or individual log files")
    ap.add_argument("-o", "--out", help="HTML output path (default plex-report.html; the "
                    "packaged executable writes next to the input instead)")
    ap.add_argument("--pdf", help="also write a PDF (needs weasyprint, wkhtmltopdf or chromium)")
    ap.add_argument("--json", dest="json_out", help="also write a JSON summary")
    ap.add_argument("--since", help="only lines newer than this: 24h, 3d, 2w, or 2026-09-09")
    ap.add_argument("--top", type=int, default=40, help="message patterns to list (default 40)")
    ap.add_argument("--redact", action="store_true",
                    help="mask IP addresses, account names and email addresses "
                         "(auth tokens are always masked)")
    frozen = bool(getattr(sys, "frozen", False))      # running as a PyInstaller build
    if frozen and not (sys.argv[1:] if argv is None else argv):
        # double-clicked with nothing to read: explain, and keep the window open
        ap.print_help()
        print("\nDrag a Plex log zip (or the Logs folder) onto plexreport, or run it from "
              "a terminal with the path as an argument.")
        pause()
        return 2
    opts = ap.parse_args(argv)
    interactive = frozen and opts.out is None
    if opts.out is None:
        opts.out = "plex-report.html"
        if interactive:
            # dragged onto the executable: the working directory is arbitrary, so put
            # the report next to whatever was dropped
            first = os.path.abspath(opts.paths[0].rstrip("/\\"))
            stem = os.path.splitext(os.path.basename(first))[0] or "plex"
            opts.out = os.path.join(os.path.dirname(first), stem + "-report.html")

    since = parse_since(opts.since)
    a = ingest(opts.paths, since=since, top=opts.top)
    if not a.files:
        raise SystemExit("no log files found in: %s" % ", ".join(opts.paths))

    out = os.path.abspath(opts.out)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render(a, opts))
    print("wrote %s  (%s lines from %d files)" % (out, num(a.total_lines), len(a.files)))

    if opts.json_out:
        with open(opts.json_out, "w", encoding="utf-8") as fh:
            json.dump(to_json(a), fh, indent=2, default=str)
        print("wrote %s" % os.path.abspath(opts.json_out))

    if opts.pdf:
        engine = write_pdf(out, opts.pdf)
        if engine:
            print("wrote %s (via %s)" % (os.path.abspath(opts.pdf), engine))
        else:
            print("no PDF engine found - open the HTML and print to PDF, or "
                  "pip install weasyprint", file=sys.stderr)
    if interactive:
        import webbrowser
        webbrowser.open("file://" + out)
        pause()
    return 0


def pause():
    try:
        input("\nPress Enter to close.")
    except (EOFError, OSError):
        pass


if __name__ == "__main__":
    sys.exit(main())
