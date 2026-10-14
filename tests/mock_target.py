"""本地模拟靶机（仅供安全测试扫描器用，不要对外网目标使用）。

用标准库起一个 HTTP 服务，故意伪造出：
    - WordPress 首页特征（wp-content / wp-includes / generator 标签 / X-Powered-By）
    - Shiro 的 rememberMe=deleteMe 回显行为（带 deleteMe Cookie 请求时，
      响应头会回写 Set-Cookie: rememberMe=deleteMe 并跳转登录页）

运行：
    python tests/mock_target.py            # 默认监听 127.0.0.1:8080
    python tests/mock_target.py 9000       # 指定端口
然后另开一个终端：
    python main.py -u http://127.0.0.1:8080 -v
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

WORDPRESS_HOME = """<!DOCTYPE html>
<html><head>
  <meta name="generator" content="WordPress 6.4.3" />
  <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
  <script src="/wp-includes/js/jquery/jquery.min.js"></script>
</head>
<body><h1>My Site</h1><a href="/wp-json/wp/v2/posts">REST API</a></body>
</html>
"""

WP_LOGIN = """<form name="loginform" action="/wp-login.php" method="post">
  <label>user_login<input id="user_login" name="log" /></label>
  <input type="submit" name="wp-submit" value="Log In" />
</form>
"""

SHIRO_LOGIN = """<html><head><title>若依后台管理系统</title></head>
<body>
  <form action="/login" method="post">ruoyi 登录</form>
  <!-- org.apache.shiro.web.filter.authc.FormAuthenticationFilter -->
</body></html>
"""


class MockHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self):  # noqa: N802 - http.server 约定的方法名
        path = urlparse(self.path).path
        cookie = self.headers.get("Cookie", "")
        has_delete_me = "rememberme=deleteme" in cookie.lower()

        if path in ("/", "/index.php"):
            self._send(200, WORDPRESS_HOME, extra={"X-Powered-By": "PHP/8.1.27"})
        elif path == "/wp-login.php":
            self._send(200, WP_LOGIN)
        elif path in ("/login", "/admin/login", "/doLogin", "/user/login"):
            if has_delete_me:
                # Shiro 命中 deleteMe 时的经典表现：回写 deleteMe 并 302
                self._send(302, "", extra={
                    "Location": "/login",
                    "Set-Cookie": "rememberMe=deleteMe; Path=/; Max-Age=0",
                }, extra_cookies=["JSESSIONID=8A1B2C3D; Path=/"])
            else:
                self._send(200, SHIRO_LOGIN,
                           extra_cookies=["JSESSIONID=8A1B2C3D; Path=/"])
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def _send(self, status, body, extra=None, extra_cookies=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        for item in extra_cookies or []:
            self.send_header("Set-Cookie", item)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, fmt, *args):  # 精简日志
        sys.stderr.write("[mock] %s\n" % (fmt % args))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = HTTPServer(("127.0.0.1", port), MockHandler)
    print(f"[mock] 模拟靶机已启动： http://127.0.0.1:{port}  （Ctrl+C 停止）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock] 已停止")


if __name__ == "__main__":
    main()
