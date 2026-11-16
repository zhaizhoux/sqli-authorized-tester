# -*- coding: utf-8 -*-
"""授权与目标安全护栏。

任何对外请求都必须先经过本模块。它负责三件事：

1. 校验 URL 协议与目标主机；
2. 按目标归属分级要求授权确认（回环 / 内网 / 公网）；
3. 对请求频率、请求总量、超时时间做硬性限制，避免对目标产生压力。

这些限制是刻意为之的产品边界，请不要在二次开发时移除。
"""
from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

CONFIRM_PHRASE = "我已知悉并获授权"

LOOPBACK_NAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0:0:0:0:0:0:0:1",
}


class GuardError(ValueError):
    """目标或授权条件不满足要求。"""


@dataclass(frozen=True)
class TargetInfo:
    url: str
    host: str
    port: int
    zone: str           # loopback | private | public
    zone_label: str


def classify_host(host: str) -> tuple[str, str]:
    """按字面量判定目标归属，不做 DNS 解析（避免引入不可控的解析结果）。"""
    h = host.strip().lower().strip("[]")
    if h in LOOPBACK_NAMES or h.endswith(".localhost"):
        return "loopback", "本机回环"
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return "public", "公网域名"
    if addr.is_loopback:
        return "loopback", "本机回环"
    if addr.is_private or addr.is_link_local:
        return "private", "内网地址"
    return "public", "公网地址"


def inspect_url(url: str) -> TargetInfo:
    if not url or not url.strip():
        raise GuardError("请填写目标 URL")
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise GuardError("仅支持 http / https 协议")
    if not parsed.hostname:
        raise GuardError("URL 中缺少主机名")
    if parsed.username or parsed.password:
        raise GuardError("URL 中不允许携带账号密码")
    zone, label = classify_host(parsed.hostname)
    default_port = 443 if parsed.scheme == "https" else 80
    return TargetInfo(
        url=url,
        host=parsed.hostname,
        port=parsed.port or default_port,
        zone=zone,
        zone_label=label,
    )


def verify_authorization(info: TargetInfo, acknowledged: bool, phrase: str = "") -> None:
    """分级授权确认。

    - 回环地址：勾选确认即可（配套内置靶场，供合法练习）；
    - 内网地址：额外要求输入确认语，防止误扫他人设备；
    - 公网地址：同样要求输入确认语，并在界面上强调必须持有书面授权。
    """
    if not acknowledged:
        raise GuardError("必须先勾选授权确认")
    if info.zone == "loopback":
        return
    if phrase.strip() != CONFIRM_PHRASE:
        if info.zone == "private":
            raise GuardError(f"内网目标需在确认框中输入「{CONFIRM_PHRASE}」")
        raise GuardError(
            f"公网目标需在确认框中输入「{CONFIRM_PHRASE}」，"
            "并确认你持有该系统所有者的书面授权"
        )


@dataclass(frozen=True)
class SafetyLimits:
    """硬性安全上限，防止工具被当作压力/批量扫描器使用。"""

    min_interval: float = 1.0        # 两次请求最小间隔（秒）
    max_requests: int = 40           # 单次任务请求总数上限
    timeout: float = 6.0             # 单次请求超时（秒）
    max_response_bytes: int = 512_000


class Interrupted(Exception):
    """用户主动停止。"""


class RequestBudget:
    """可中断的限速 / 限量控制器。"""

    def __init__(self, limits: SafetyLimits, stop_event: threading.Event | None = None):
        self.limits = limits
        self.stop_event = stop_event or threading.Event()
        self._last = 0.0
        self._count = 0
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        return self._count

    def acquire(self) -> None:
        if self.stop_event.is_set():
            raise Interrupted("已停止")
        with self._lock:
            if self._count >= self.limits.max_requests:
                raise GuardError(
                    f"已达到单次任务请求上限（{self.limits.max_requests} 次），任务自动结束"
                )
            now = time.monotonic()
            wait = self.limits.min_interval - (now - self._last)
            if wait > 0 and self._last:
                # 用 Event.wait 实现可中断的等待，停止按钮能立刻生效
                if self.stop_event.wait(wait):
                    raise Interrupted("已停止")
            self._last = time.monotonic()
            self._count += 1
