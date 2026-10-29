"""Loopback upload recorder for the offline generation contract tests."""
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

ID = "11111111-1111-4111-8111-111111111111"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        target = urlsplit(self.path).query
        digest = hashlib.sha256(payload).hexdigest()
        expected = "ci1-" + hashlib.sha256(
            f"{digest}\n{target}\nci-upload/1".encode()
        ).hexdigest()
        assert self.headers["Idempotency-Key"] == expected
        assert self.headers["Content-Type"] == "application/vnd.cyclonedx+json"
        assert self.headers["X-Cracken-Client"] == "ci-upload/1"
        with open(sys.argv[2], "a") as records:
            records.write(json.dumps({"digest": digest, "key": expected,
                                      "body": json.loads(payload)}) + "\n")
        body = json.dumps({"analysis_id": ID, "sbom_upload_id": ID,
                           "status": "queued"}).encode()
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as port:
    port.write(str(server.server_port))
server.serve_forever()
