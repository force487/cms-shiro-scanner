"""数据模型：HTTP 响应对象与扫描结果对象。

这两个类是整个扫描器各模块之间传递数据的“通用语言”：
    - HttpResponse  : 一次 HTTP 请求的原始结果（状态码/响应头/正文/耗时）
    - Finding       : 一个模块给出的一个结论（指纹命中 / Shiro 命中）
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class HttpResponse:
    """一次 HTTP 请求的结构化结果。"""

    url: str = ""                                   # 实际请求的完整 URL
    status: int = 0                                 # HTTP 状态码，0 表示请求失败
    headers: Dict[str, str] = field(default_factory=dict)  # 响应头，key 统一小写
    set_cookies: List[str] = field(default_factory=list)   # 所有 Set-Cookie 原始串
    body: str = ""                                  # 响应正文（已按 utf-8/gbk 解码）
    elapsed: float = 0.0                            # 请求耗时（秒）
    error: str = ""                                 # 出错信息，非空表示请求失败

    @property
    def ok(self) -> bool:
        """请求是否成功拿到响应。"""
        return self.error == "" and self.status > 0

    def header(self, name: str, default: str = "") -> str:
        """按名字取响应头（忽略大小写）。"""
        return self.headers.get(name.lower(), default)

    def set_cookie_text(self) -> str:
        """把所有 Set-Cookie 拼成一个字符串，便于做关键字包含判断。"""
        return " ; ".join(self.set_cookies)

    def is_shiro_delete_me(self) -> bool:
        """响应里是否回显了 rememberMe=deleteMe（Shiro 的典型特征）。"""
        return "rememberme=deleteme" in self.set_cookie_text().lower().replace(" ", "")


@dataclass
class Finding:
    """一个扫描结论。"""

    module: str                       # 来自哪个模块：cms / shiro
    name: str                         # 结论名称，例如 "WordPress" / "Apache Shiro"
    confidence: str = "low"           # high / medium / low
    score: int = 0                    # 命中权重总分
    evidence: List[str] = field(default_factory=list)  # 命中证据（人话描述）
    url: str = ""                     # 结论对应的 URL

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "name": self.name,
            "confidence": self.confidence,
            "score": self.score,
            "url": self.url,
            "evidence": self.evidence,
        }
