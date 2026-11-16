# -*- coding: utf-8 -*-
"""联调自测：验证靶场与检测引擎的预期行为。

    python tests/smoke_test.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import engine, guard, payloads  # noqa: E402
from lab import lab_server  # noqa: E402


def make_scanner(url: str, modes: tuple[str, ...]):
    events: list[tuple[str, dict]] = []
    stop = threading.Event()
    cfg = engine.Config(
        url=url,
        param="id",
        method="GET",
        modes=modes,
        limits=guard.SafetyLimits(min_interval=0.05, timeout=8.0, max_requests=40),
    )
    scanner = engine.Scanner(cfg, lambda kind, data: events.append((kind, data)), stop)
    return scanner, events


def main() -> int:
    # 换一个端口，避免与正在运行的 GUI 靶场冲突
    server = lab_server.start_server(port=0)
    port = server.server_address[1]
    lab_server.serve_in_background(server)
    base = f"http://{lab_server.HOST}:{port}"
    print(f"临时靶场：{base}")

    ok = True
    try:
        # 1) 参数化查询端点：不应检出注入点
        safe_scanner, safe_events = make_scanner(
            f"{base}/safe", ("error", "boolean", "time")
        )
        safe_scanner.run()
        done = [d for k, d in safe_events if k == "done"]
        assert done, "未收到 done 事件"
        print(f"/safe  线索数={len(done[0]['findings'])} 结论={done[0]['verdict']}")
        if done[0]["findings"]:
            print("  ✗ 参数化端点不应检出注入点")
            ok = False
        else:
            print("  ✓ 参数化端点干净")

        # 2) 拼接查询端点：三类线索都应出现
        bad_scanner, bad_events = make_scanner(
            f"{base}/search", ("error", "boolean", "time")
        )
        bad_scanner.run()
        done = [d for k, d in bad_events if k == "done"]
        assert done, "未收到 done 事件"
        cats = {f["category"] for f in done[0]["findings"]}
        print(f"/search 线索数={len(done[0]['findings'])} 类型={sorted(cats)}")
        for expected in ("报错型", "布尔盲注", "时间盲注"):
            if expected in cats:
                print(f"  ✓ 检出 {expected}")
            else:
                print(f"  ✗ 未检出 {expected}")
                ok = False

        # 3) 授权护栏
        try:
            guard.verify_authorization(
                guard.inspect_url("https://example.com/a"), False, ""
            )
            print("  ✗ 未勾选授权却通过了校验")
            ok = False
        except guard.GuardError:
            print("  ✓ 授权护栏生效")
        try:
            guard.verify_authorization(
                guard.inspect_url("https://example.com/a"), True, "随便写的"
            )
            print("  ✗ 错误确认语却通过了校验")
            ok = False
        except guard.GuardError:
            print("  ✓ 公网确认语生效")

        # 4) 载荷库完整性
        assert payloads.ERROR_PAYLOADS and payloads.BOOLEAN_PAIRS and payloads.TIME_PAYLOADS
        print("  ✓ 载荷库完整")
    finally:
        server.shutdown()
        server.server_close()

    print("\n自测结果：", "全部通过" if ok else "存在失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
