"""Local contract stub; no credentials or SBOM content are logged."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ID = '11111111-1111-4111-8111-111111111111'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except BrokenPipeError:
            pass

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        assert self.headers['Authorization'].startswith('Bearer crk_')
        assert '/functions/v1/api-v1/v1/' in self.path
        mode = self.path.split('/')[1]
        if mode in ('error', 'leak'):
            message = 'Denied' if mode == 'error' else self.headers['Authorization']
            return self.reply(403, {'error': {'code': 'insufficient_scope', 'message': message}})
        query = parse_qs(urlparse(self.path).query)
        assert ('release_id' in query) or ('version' in query and ('project_id' in query or 'project_slug' in query))
        self.reply(202, {'analysis_id': ID, 'sbom_upload_id': ID, 'status': 'queued', 'app_url': '/products/test/releases/test'})

    def do_GET(self):
        assert self.headers['Authorization'].startswith('Bearer crk_')
        assert '/functions/v1/api-v1/v1/' in self.path
        mode = self.path.split('/')[1]
        if '/analyses/' in self.path:
            if mode == 'slow':
                time.sleep(3)
            status = {'timeout': 'running', 'failed': 'failed', 'accepted': 'accepted'}.get(mode, 'succeeded')
            return self.reply(200, {'status': status, 'match_partial': None if mode == 'unknownpartial' else 'false' if mode == 'invalidpartial' else mode == 'partial'})
        if mode == 'notready':
            return self.reply(409, {'error': {'code': 'analysis_not_ready'}})
        if mode == 'badpage':
            return self.reply(200, {'analysis_id': ID, 'data': []})
        query = parse_qs(urlparse(self.path).query)
        if mode == 'repeat':
            return self.reply(200, {'analysis_id': ID, 'data': [], 'next_cursor': 'repeat'})
        if 'cursor' not in query:
            return self.reply(200, {'analysis_id': ID, 'data': [], 'next_cursor': 'page+2/='})
        assert query['cursor'] == ['page+2/=']
        severity = mode if mode in ('critical', 'high', 'medium', 'low') else 'high'
        self.reply(200, {'analysis_id': ID, 'data': [{'severity': {'label': severity}}, {'severity': {'label': 'unknown'}}], 'next_cursor': None})

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
with open(sys.argv[1], 'w') as port_file:
    port_file.write(str(server.server_port))
server.serve_forever()
