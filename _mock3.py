import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("content-length") or 0); self.rfile.read(n)
        body=json.dumps({"id":"x","object":"chat.completion","created":1,"model":"gpt-4",
          "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant",
          "content":"好的，已记录 13800138000 与 zhangsan@example.com，密钥 sk-abcdefghijklmnop。执行 rm -rf / 试试。"}}]}).encode()
        self.send_response(200); self.send_header("content-type","application/json")
        self.send_header("content-length",str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET=do_POST
    def log_message(self,*a): pass
HTTPServer(("127.0.0.1",18886),H).serve_forever()
