"""
capture.py — captures only DVWA traffic via dvwa.local hostname.

Run with:
    # Legit traffic:
    mitmdump -s data/capture.py --listen-host 127.0.0.1 --listen-port 8080 `
             --set outfile=data/traffic_legit.jsonl --set label=0

    # Attack traffic:
    mitmdump -s data/capture.py --listen-host 127.0.0.1 --listen-port 8080 `
             --set outfile=data/traffic_attack.jsonl --set label=1
"""

import json
import datetime
import mitmproxy.http
from mitmproxy import ctx

# dvwa.local instead of localhost — Firefox proxies this normally
ALLOWED_HOSTS = {"dvwa.local", "dvwa.local:80"}


class RequestCapture:

    def load(self, loader):
        loader.add_option("outfile", str, "data/traffic_legit.jsonl", "Output JSONL file")
        loader.add_option("label",   int, 0,                          "0=legit, 1=attack")

    def request(self, flow: mitmproxy.http.HTTPFlow):
        host = flow.request.pretty_host

        # Drop everything that isn't DVWA
        if host not in ALLOWED_HOSTS:
            return

        req = flow.request

        record = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "label":     ctx.options.label,
            "method":    req.method,
            "host":      host,
            "path":      req.path,
            "query":     dict(req.query),
            "body":      req.get_text() or " ",
            "headers": {
                k.lower(): v
                for k, v in req.headers.items()
                if k.lower() in (
                    "content-type", "user-agent",
                    "cookie",        "referer",
                    "x-forwarded-for"
                )
            },
        }

        with open(ctx.options.outfile, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        print(f"[label={record['label']}] {record['method']} {host}{record['path']}")


addons = [RequestCapture()]