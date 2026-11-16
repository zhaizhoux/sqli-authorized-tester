# -*- coding: utf-8 -*-
"""SQL 注入点探测引擎。

能力边界（刻意为之）：
- 只判断「某参数是否可能被拼接进 SQL」，即注入点探测；
- 不做数据提取、库表枚举、凭据读取、WAF 绕过、批量目标扫描；
- 所有请求经过 RequestBudget 限速与限量；
- 结论一律标注为「疑似 / 需人工复核」，不替代代码审计与完整渗透测试。
"""
from __future__ import annotations

import difflib
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import requests

from .guard import GuardError, Interrupted, RequestBudget, SafetyLimits
from .payloads import (
    BOOLEAN_PAIRS,
    DB_ERROR_SIGNATURES,
    DEFENSE_TIPS,
    DISCLAIMER_SHORT,
    ERROR_PAYLOADS,
    GENERIC_SIGNATURES,
    TIME_PAYLOADS,
)

USER_AGENT = "SQLiScope/1.0 (Authorized-Self-Check; single-target; rate-limited)"

Emitter = Callable[[str, dict[str, Any]], None]


@dataclass
class Config:
    url: str
    param: str = "id"
    method: str = "GET"
    extra_params: dict[str, str] = field(default_factory=dict)
    modes: tuple[str, ...] = ("error", "boolean", "time")
    baseline_value: str = "1"
    limits: SafetyLimits = field(default_factory=SafetyLimits)


@dataclass
class Finding:
    category: str
    payload: str
    confidence: str
    evidence: str
    note: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "payload": self.payload,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "note": self.note,
        }


@dataclass
class Response:
    status: int
    length: int
    body: str
    sha: str
    elapsed: float


def _similarity(a: str, b: str) -> float:
    """对截断后的响应正文做相似度比较，避免大页面拖慢速度。"""
    left, right = a[:4000], b[:4000]
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()


class Scanner:
    """单次、单目标、可中断的探测任务。"""

    def __init__(self, cfg: Config, emit: Emitter, stop_event: threading.Event):
        self.cfg = cfg
        self.emit = emit
        self.stop_event = stop_event
        self.budget = RequestBudget(cfg.limits, stop_event)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/json,*/*",
                "X-SQLiScope-Purpose": "authorized-self-check",
            }
        )
        self.findings: list[Finding] = []
        self._total_steps = 1 + (
            len(ERROR_PAYLOADS) if "error" in cfg.modes else 0
        ) + (
            len(BOOLEAN_PAIRS) * 2 if "boolean" in cfg.modes else 0
        ) + (
            len(TIME_PAYLOADS) * 2 if "time" in cfg.modes else 0
        )
        self._steps = 0

    # ---------------- 基础请求 ----------------
    def _log(self, text: str, level: str = "info") -> None:
        self.emit("log", {"level": level, "text": text})

    def _tick(self, text: str) -> None:
        self._steps += 1
        self.emit(
            "progress",
            {"value": self._steps, "max": self._total_steps, "text": text},
        )

    def _request(self, value: str) -> Response:
        self.budget.acquire()
        params = dict(self.cfg.extra_params)
        params[self.cfg.param] = value
        try:
            if self.cfg.method.upper() == "POST":
                resp = self.session.post(
                    self.cfg.url, data=params, timeout=self.cfg.limits.timeout
                )
            else:
                resp = self.session.get(
                    self.cfg.url, params=params, timeout=self.cfg.limits.timeout
                )
        except requests.RequestException as exc:
            raise RuntimeError(f"请求失败，请检查目标是否可达：{exc}") from exc
        body = resp.text[: self.cfg.limits.max_response_bytes]
        return Response(
            status=resp.status_code,
            length=len(body),
            body=body,
            sha=hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            elapsed=resp.elapsed.total_seconds(),
        )

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.emit("finding", finding.as_dict())

    # ---------------- 三类探测 ----------------
    def _probe_errors(self, baseline: Response) -> None:
        self._log("— 开始报错型探测 —")
        base_lower = baseline.body.lower()
        for item in ERROR_PAYLOADS:
            self._tick(f"报错型：{item.value}")
            try:
                resp = self._request(item.value)
            except RuntimeError:
                raise
            lower = resp.body.lower()
            matched = [sig for sig in DB_ERROR_SIGNATURES if sig in lower]
            # 基线里本来就有的文本不算证据
            matched = [sig for sig in matched if sig not in base_lower]
            server_error = resp.status >= 500 and baseline.status < 500
            if not matched and not server_error:
                self._log(f"  [{item.value}] 无异常回显")
                continue
            if matched and all(sig in GENERIC_SIGNATURES for sig in matched):
                confidence = "低"
            elif len(matched) >= 2 or server_error:
                confidence = "高"
            else:
                confidence = "中"
            evidence = (
                f"HTTP {resp.status}，响应 {resp.length} 字节；"
                f"命中报错特征：{', '.join(matched) if matched else '仅服务端 5xx'}"
            )
            self._add(
                Finding(
                    category="报错型",
                    payload=item.value,
                    confidence=confidence,
                    evidence=evidence,
                    note=f"{item.note}。建议关闭详细报错并改用参数化查询。",
                )
            )
            self._log(f"  [{item.value}] 发现报错特征（{confidence}置信）", "warn")

    def _probe_boolean(self, baseline: Response) -> None:
        self._log("— 开始布尔盲注探测 —")
        for pair in BOOLEAN_PAIRS:
            self._tick(f"布尔对比：{pair.true_payload.value}")
            true_resp = self._request(pair.true_payload.value)
            self._tick(f"布尔对比：{pair.false_payload.value}")
            false_resp = self._request(pair.false_payload.value)

            sim = _similarity(true_resp.body, false_resp.body)
            len_delta = abs(true_resp.length - false_resp.length)
            sim_true_base = _similarity(true_resp.body, baseline.body)
            sim_false_base = _similarity(false_resp.body, baseline.body)
            delta = sim_true_base - sim_false_base

            # 永真响应更接近基线、且与永假响应有明显差异，才视为有效信号
            if sim >= 0.97 and len_delta == 0:
                self._log(f"  [{pair.note}] 两种条件响应一致，无差异")
                continue
            if delta <= 0.02:
                self._log(f"  [{pair.note}] 响应有差异但不符合注入特征，跳过")
                continue
            confidence = "高" if delta >= 0.25 else ("中" if delta >= 0.08 else "低")
            self._add(
                Finding(
                    category="布尔盲注",
                    payload=f"{pair.true_payload.value}  ⟷  {pair.false_payload.value}",
                    confidence=confidence,
                    evidence=(
                        f"永真/永假响应相似度 {sim:.2f}，长度差 {len_delta} 字节，"
                        f"与基线相似度 {sim_true_base:.2f} / {sim_false_base:.2f}"
                    ),
                    note=f"{pair.note}。差异也可能来自业务本身，务必人工复核。",
                )
            )
            self._log(f"  [{pair.note}] 检测到条件差异（{confidence}置信）", "warn")

    def _probe_time(self, baseline: Response) -> None:
        self._log("— 开始时间盲注探测 —")
        for item in TIME_PAYLOADS:
            self._tick(f"延时探测：{item.value}")
            try:
                resp = self._request(item.value)
            except requests.exceptions.Timeout:
                self._log(f"  [{item.dialect}] 请求超时，跳过该载荷", "warn")
                self._tick("延时复核")
                continue
            self._tick(f"延时复核：{item.value}")
            threshold = max(1.4, baseline.elapsed + 1.2)
            if resp.elapsed < threshold:
                self._log(f"  [{item.dialect}] {resp.elapsed:.2f}s，未达阈值 {threshold:.2f}s")
                continue
            # 用一次正常请求排除网络抖动造成的偶发慢响应
            confirm = self._request(self.cfg.baseline_value)
            if confirm.elapsed >= threshold:
                self._log("  复核请求同样缓慢，判定为网络抖动，不记录", "warn")
                continue
            self._add(
                Finding(
                    category="时间盲注",
                    payload=item.value,
                    confidence="高",
                    evidence=(
                        f"注入载荷耗时 {resp.elapsed:.2f}s，"
                        f"基线 {baseline.elapsed:.2f}s，复核 {confirm.elapsed:.2f}s"
                    ),
                    note=f"{item.note}。该载荷仅适用于 {item.dialect}。",
                )
            )
            self._log(f"  [{item.dialect}] 检测到可复现延时", "warn")

    # ---------------- 主流程 ----------------
    @staticmethod
    def verdict(findings: list[Finding]) -> str:
        if any(f.confidence == "高" for f in findings):
            return "高概率存在 SQL 注入点，请立即修复并人工复核"
        if findings:
            return "发现疑似迹象，需人工复核（可能存在误报）"
        return "未发现明显注入迹象（不代表绝对安全，请结合代码审计）"

    def run(self) -> None:
        started = datetime.now().astimezone().isoformat(timespec="seconds")
        self._log(f"目标：{self.cfg.url}  参数：{self.cfg.param}  方法：{self.cfg.method}")
        self._log(
            f"限速 {self.cfg.limits.min_interval}s/次，上限 {self.cfg.limits.max_requests} 次，"
            f"单目标模式"
        )
        try:
            self._tick("建立基线响应")
            baseline = self._request(self.cfg.baseline_value)
            self._log(
                f"基线：HTTP {baseline.status}，{baseline.length} 字节，"
                f"{baseline.elapsed:.2f}s"
            )
            if "error" in self.cfg.modes:
                self._probe_errors(baseline)
            if "boolean" in self.cfg.modes:
                self._probe_boolean(baseline)
            if "time" in self.cfg.modes:
                self._probe_time(baseline)
        except Interrupted:
            self.emit("aborted", {"text": "用户已停止，任务提前结束"})
            return
        except GuardError as exc:
            self._log(f"安全护栏：{exc}", "warn")
        except RuntimeError as exc:
            self.emit("error", {"text": str(exc)})
            return
        finally:
            self.session.close()

        summary = self.verdict(self.findings)
        self._log(f"任务结束，共发出 {self.budget.count} 次请求，发现 {len(self.findings)} 条线索")
        self._log(f"结论：{summary}", "warn")
        self.emit(
            "done",
            {
                "started": started,
                "finished": datetime.now().astimezone().isoformat(timespec="seconds"),
                "target": self.cfg.url,
                "param": self.cfg.param,
                "method": self.cfg.method,
                "modes": list(self.cfg.modes),
                "request_count": self.budget.count,
                "verdict": summary,
                "findings": [f.as_dict() for f in self.findings],
                "defense_tips": [{"title": t, "detail": d} for t, d in DEFENSE_TIPS],
                "disclaimer": DISCLAIMER_SHORT,
            },
        )
