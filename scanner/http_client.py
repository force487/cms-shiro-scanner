"""HTTP 客户端：只用标准库 urllib，不需要安装任何第三方依赖。

对外只暴露一个 get() 方法，返回 models.HttpResponse。
所有模块（CMS / Shiro）都通过它发请求，方便统一控制超时、UA、TLS 校验和重定向。
"""

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from .models import HttpResponse

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随跳转，这样我们能拿到 3xx 的响应头和 Location。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class HttpClient:
    """简易 HTTP 客户端。"""

    def __init__(
        self,
        timeout: float = 8.0,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = False,
        follow_redirect: bool = True,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.follow_redirect = follow_redirect

        ctx = ssl.create_default_context()
        if not verify_tls:
            # 扫描场景下目标常用自签名证书，默认不做 TLS 校验
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        handler = urllib.request.HTTPSHandler(context=ctx)
        self._opener_follow = urllib.request.build_opener(handler)
        # 关闭重定向的 opener：Shiro 探测必须用它，否则 302 上的
        # Set-Cookie: rememberMe=deleteMe 会在跳转过程中丢掉
        self._opener_plain = urllib.request.build_opener(_NoRedirect, handler)
        self._opener = self._opener_follow if follow_redirect else self._opener_plain

    # ------------------------------------------------------------------ #
    # 公开接口
    # ------------------------------------------------------------------ #
    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        follow_redirect: Optional[bool] = None,
    ) -> HttpResponse:
        """发一个 GET 请求，任何异常都不会抛出，而是记录在 HttpResponse.error 里。

        follow_redirect 为 None 时使用客户端默认策略，传 False 可临时关闭跳转跟随。
        """
        url = normalize_url(url)
        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)
        if cookies:
            # 手动拼 Cookie 头，避免引入 CookieJar 的额外状态
            req_headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in cookies.items()
            )

        request = urllib.request.Request(url, headers=req_headers, method="GET")
        opener = self._opener
        if follow_redirect is True:
            opener = self._opener_follow
        elif follow_redirect is False:
            opener = self._opener_plain

        start = time.time()
        try:
            with opener.open(request, timeout=self.timeout) as resp:
                raw = resp.read()
                return self._build(url, resp.status, resp.headers, raw, start)
        except urllib.error.HTTPError as exc:
            # 4xx / 5xx（以及关闭重定向后的 3xx）都会走到这里
            raw = exc.read() if hasattr(exc, "read") else b""
            return self._build(url, exc.code, exc.headers, raw, start)
        except Exception as exc:  # noqa: BLE001 - 扫描器不能被单个目标打断
            return HttpResponse(
                url=url, status=0, error=f"{type(exc).__name__}: {exc}",
                elapsed=time.time() - start,
            )

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    def _build(self, url, status, headers, raw: bytes, start: float) -> HttpResponse:
        hmap: Dict[str, str] = {}
        for key, value in headers.items():
            name = key.lower()
            # 同名响应头可能有多个（典型的是 Set-Cookie），这里合并而不是覆盖
            hmap[name] = f"{hmap[name]}, {value}" if name in hmap else value
        set_cookies: List[str] = headers.get_all("Set-Cookie") or []
        return HttpResponse(
            url=url,
            status=status,
            headers=hmap,
            set_cookies=set_cookies,
            body=decode_body(raw, hmap.get("content-type", "")),
            elapsed=time.time() - start,
        )


def normalize_url(url: str) -> str:
    """补全协议头，并去掉多余空白。"""
    url = (url or "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url


def join_url(base: str, path: str) -> str:
    """把站点根地址和目标路径拼成一个完整 URL。"""
    base = normalize_url(base)
    if path.lower().startswith("http://") or path.lower().startswith("https://"):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def decode_body(raw: bytes, content_type: str) -> str:
    """尽量把字节流解码成可搜索的文本。"""
    if not raw:
        return ""
    charset = "utf-8"
    lowered = content_type.lower()
    if "gbk" in lowered or "gb2312" in lowered:
        charset = "gbk"
    for enc in (charset, "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")
