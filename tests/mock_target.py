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

import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

WORDPRESS_HOME = """<!DOCTYPE html>
<html><head>
  <meta name="generator" content="WordPress 6.4.3" />
  <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
  <script src="/wp-includes/js/jquery/jquery.min.js"></script>
</head>
<body><h1>My Site</h1><a href="/wp-json/wp/v2/posts">REST API</a>
<a href="/search?id=1">站内搜索</a>
<a href="/reflect?q=hello">留言板</a>
<a href="/ping?host=127.0.0.1">网络诊断</a>
<a href="/view?file=about.txt">查看页面</a>
<form action="/upload" method="post" enctype="multipart/form-data">
  上传：<input type="file" name="file"><input type="submit" value="上传">
</form></body>
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


# 保存上传的文件，模拟"上传后可通过 /uploads/<name> 访问并执行"
UPLOADED = {}

# 敏感路径内容，模拟"泄露的敏感文件 / 目录"
SENSITIVE_FILES = {
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true",
    "/.svn/entries": "12\ndir\n2026-01-01T00:00:00.000000Z\n",
    "/.env": "APP_NAME=Laravel\nAPP_KEY=base64:abcdef0123456789\n",
    "/phpinfo.php": "phpinfo()\nPHP Version 8.1.27\nSystem: Windows NT",
    "/web.config": "<configuration>\n  <system.webServer>\n  </system.webServer>\n</configuration>",
    "/robots.txt": "User-agent: *\nDisallow: /admin\n",
    "/backup.zip": "PK (zip 二进制占位)",
    "/admin": "<html><body><h1>后台管理</h1></body></html>",
}


def parse_multipart(body, content_type):
    """极简 multipart 解析：返回 (filename, content)。"""
    if not content_type:
        return None, b""
    m = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type)
    if not m:
        return None, b""
    boundary = (m.group(1) or m.group(2)).strip()
    boundary_bytes = ("--" + boundary).encode("utf-8")
    filename = None
    content = b""
    for part in body.split(boundary_bytes):
        if b"filename=" in part:
            fn = re.search(rb'filename="([^"]+)"', part)
            if fn:
                filename = fn.group(1).decode("utf-8", "replace")
            idx = part.find(b"\r\n\r\n")
            if idx != -1:
                content = part[idx + 4:].rstrip(b"\r\n")
    return filename, content


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
        elif path == "/search":
            # 故意留一个 SQL 注入点：参数值混入 SQL 特征时回显数据库报错
            id_value = "".join(parse_qs(urlparse(self.path).query).get("id", []))
            lowered = id_value.lower()
            if ("'" in id_value or "updatexml" in lowered or "extractvalue" in lowered
                    or "union" in lowered or "order by" in lowered):
                self._send(500, "You have an error in your SQL syntax; check the "
                                "manual that corresponds to your MySQL server "
                                "version for the right syntax to use near ''' at line 1")
            else:
                self._send(200, "<html><body><h1>搜索结果</h1><p>没有找到相关记录。</p></body></html>")
        elif path == "/reflect":
            # 故意不转义，把 q 原样反射进 HTML —— 用来验证反射型 XSS 检测
            q = "".join(parse_qs(urlparse(self.path).query).get("q", []))
            self._send(200, f"<html><body><h1>留言板</h1><p>内容：{q}</p></body></html>")
        elif path == "/ping":
            # 故意把 host 参数拼进 shell 命令 —— 用来验证命令注入检测
            host = "".join(parse_qs(urlparse(self.path).query).get("host", []))
            m = re.search(r"echo\s+([a-z0-9]+)", host, re.IGNORECASE)
            if m:
                self._send(200, f"PING 结果：{m.group(1)} 可达（模拟命令执行）")
            else:
                self._send(200, f"PING {host or '127.0.0.1'}: 正常")
        elif path == "/view":
            # 故意把 file 参数当文件路径读取 —— 用来验证文件包含检测
            f = "".join(parse_qs(urlparse(self.path).query).get("file", []))
            lowered = f.lower()
            if "passwd" in lowered:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\n"
                                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin")
            elif "hosts" in lowered:
                self._send(200, "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback")
            elif "win.ini" in lowered or "windows" in lowered:
                self._send(200, "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]")
            else:
                self._send(200, "<html><body><h1>关于我们</h1><p>这是静态页面内容。</p></body></html>")
        elif path in SENSITIVE_FILES:
            self._send(200, SENSITIVE_FILES[path])
        elif path.startswith("/uploads/"):
            name = path.split("/")[-1]
            content = UPLOADED.get(name)
            if content is not None:
                # 模拟"执行"：直接把上传文件内容回显出来
                self._send(200, content.decode("utf-8", "replace"))
            else:
                self._send(404, "<html><body>404 Not Found</body></html>")
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

    def do_POST(self):  # noqa: N802 - http.server 约定的方法名
        path = urlparse(self.path).path
        if path == "/upload":
            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length)
            filename, content = parse_multipart(body, content_type)
            if filename and content:
                UPLOADED[filename] = content
                self._send(200, f"上传成功！文件保存在 /uploads/{filename}")
            else:
                self._send(400, "上传失败：未解析到文件")
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
