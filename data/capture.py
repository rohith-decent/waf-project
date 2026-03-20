import json
import datetime


class RequestCapture:
    """
    mitmproxy calls request() for every HTTP request it intercepts.
    We pull out the fields we care about and print them.
    """

    def request(self, flow):
        req = flow.request

        # Build a structured record — same shape we'll write to JSONL in Week 2
        record = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "method":    req.method,           # GET, POST, etc.
            "host":      req.pretty_host,      # e.g. localhost
            "path":      req.path,             # e.g. /dvwa/login.php
            "query":     dict(req.query),      # dict of query params
            "body":      req.get_text() or "", # POST body text
            "headers": {
                # Grab the headers that matter most for WAF analysis
                k: v for k, v in req.headers.items()
                if k.lower() in ("content-type", "user-agent", "cookie", "referer")
            },
        }

        # Pretty-print to console so you can see it working
        print(json.dumps(record, indent=2))
        print("-" * 60)


# mitmproxy discovers addons via this variable name — don't rename it
addons = [RequestCapture()]