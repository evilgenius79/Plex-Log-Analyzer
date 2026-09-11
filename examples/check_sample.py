#!/usr/bin/env python3
"""
check_sample.py - the repo's one test. Regenerates the fictional sample logs, runs
plexreport over them and checks the result is what the sample was built to produce.

    python3 examples/check_sample.py                    # tests plexreport.py
    python3 examples/check_sample.py dist/plexreport    # tests a packaged build

Expected: every findings rule fires, no line is unparsed, both session reports load.
If you add a findings rule, add a line to make_sample_logs.py that triggers it and
bump FINDINGS below.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXPECTED = dict(findings=17, unparsed=0, sessions=2)


def main(tool):
    with tempfile.TemporaryDirectory() as tmp:
        logs = os.path.join(tmp, "sample-logs")
        report = os.path.join(tmp, "report.html")
        summary = os.path.join(tmp, "summary.json")
        subprocess.check_call([sys.executable, os.path.join(HERE, "make_sample_logs.py"), logs])
        subprocess.check_call(tool + [logs, "-o", report, "--json", summary])
        with open(summary, encoding="utf-8") as fh:
            d = json.load(fh)
        got = dict(findings=len(d["findings"]), unparsed=d["unparsed"],
                   sessions=len(d["sessions"]))
        ok = got == EXPECTED
        print("expected %s\n     got %s  -> %s" % (EXPECTED, got, "OK" if ok else "FAIL"))
        if ok and os.path.getsize(report) < 10000:
            print("report is suspiciously small (%d bytes)" % os.path.getsize(report))
            ok = False
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or [sys.executable, os.path.join(ROOT, "plexreport.py")]))
