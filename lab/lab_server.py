# -*- coding: utf-8 -*-
"""故意存在 SQL 注入缺陷的本地教学靶场。

只监听 127.0.0.1，数据全部放在内存里的临时 SQLite 库，不写磁盘、不联网。
配套提供 /search（字符串拼接，有漏洞）与 /safe（参数化查询，已修复），
用于直观对比「错误写法」和「正确写法」。

可独立运行：python lab/lab_server.py
也可被 GUI 内嵌调用：from lab.lab_server import start_server
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8765

INDEX_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>SQLiScope 本地靶场</title>
<style>
 body{font-family:"Microsoft YaHei",system-ui,sans-serif;background:#f5f7fa;color:#1f2937;
      max-width:820px;margin:48px auto;padding:0 20px;line-height:1.7}
 h1{color:#1d4ed8;font-size:26px;margin-bottom:4px}
 .sub{color:#6b7280;margin-top:0}
 .card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px 24px;margin:18px 0;
       box-shadow:0 1px 3px rgba(0,0,0,.05)}
 code{background:#eef2ff;padding:2px 6px;border-radius:4px;color:#3730a3}
 input{padding:8px 10px;border:1px solid #d1d5db;border-radius:6px;width:220px}
 button{padding:8px 16px;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}
 a{color:#2563eb} .tag{font-size:12px;padding:2px 8px;border-radius:99px}
 .bad{background:#fee2e2;color:#b91c1c}.good{background:#dcfce7;color:#15803d}
</style></head><body>
<h1>SQLiScope 本地靶场</h1>
<p class="sub">仅监听 127.0.0.1 · 内存数据库 · 不写磁盘 · 不联网</p>
<div class="card"><b>① 有漏洞的写法 <span class="tag bad">vulnerable</span></b>
<p><code>SELECT ... WHERE id = '" + value + "'</code> —— 字符串直接拼接。</p>
<form action="/search" method="get"><input name="id" value="1"><button type="submit">查询 /search</button></form>
</div>
<div class="card"><b>② 修复后的写法 <span class="tag good">safe</span></b>
<p><code>SELECT ... WHERE id = ?</code> —— 参数化查询，输入永远只是数据。</p>
<form action="/safe" method="get"><input name="id" value="1"><button type="submit">查询 /safe</button></form>
</div>
<div class="card"><b>试试这些输入</b><p>
<code>1</code> 正常 · <code>'</code> 触发报错 ·
<code>1' AND '1'='1</code> 与 <code>1' AND '1'='2</code> 布尔差异 ·
<code>1' AND SLEEP(2) -- </code> 延时
</p><p><a href="/health">/health</a> 健康检查</p></div>
</body></html>"""


def _sleep_fn(seconds: object) -> int:
    """注册给 SQLite 的延时函数，模拟 MySQL SLEEP / PostgreSQL pg_sleep。"""
    try:
        delay = max(0.0, min(float(str(seconds)), 3.0))
    except (TypeError, ValueError):
        return 0
    time.sleep(delay)
    return 0


def _new_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    # deterministic=False 防止 SQLite 把函数折叠成常量而跳过执行
    conn.create_function("SLEEP", 1, _sleep_fn, deterministic=False)
    conn.create_function("PG_SLEEP", 1, _sleep_fn, deterministic=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [
            (1, "张三", "zhangsan@example.test"),
            (2, "李四", "lisi@example.test"),
            (3, "王五", "wangwu@example.test"),
        ],
    )
    conn.commit()
    return conn


def run_query(value: str, vulnerable: bool) -> dict:
    """返回统一结构的结果；故意把 SQL 报错回显出来，用于演示报错型注入。"""
    sql = ""
    conn = _new_connection()
    try:
        if vulnerable:
            sql = f"SELECT id, name, email FROM users WHERE id = '{value}'"
            cursor = conn.execute(sql)
        else:
            sql = "SELECT id, name, email FROM users WHERE id = ?"
            cursor = conn.execute(sql, (value,))
        rows = [
            {"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()
        ]
        return {"ok": True, "mode": "vulnerable" if vulnerable else "safe", "sql": sql, "rows": rows}
    except Exception as exc:  # noqa: BLE001 - 靶场需要把原始报错回显出来
        return {
            "ok": False,
            "mode": "vulnerable" if vulnerable else "safe",
            "sql": sql,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "SQLiScopeLab/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        # GUI 内嵌运行时 stdout/stderr 可能为空，直接屏蔽访问日志
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._send(status, data, "application/json; charset=utf-8")

    def _params(self) -> dict[str, str]:
        parsed = urlparse(self.path)
        result = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        if self.command == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(min(length, 8192)).decode("utf-8", "replace")
            result.update(
                {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
            )
        return result

    def _handle(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/health":
            self._send_json({"ok": True, "service": "SQLiScope 本地靶场", "host": HOST})
            return
        if path in ("/search", "/safe"):
            params = self._params()
            result = run_query(params.get("id", "1"), vulnerable=(path == "/search"))
            self._send_json(result)
            return
        self._send_json({"ok": False, "error": "未知路径"}, 404)

    def do_GET(self) -> None:  # noqa: N802 - 标准库约定
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()


def start_server(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    """创建（但不阻塞）靶场服务器；调用方需要自行启动 serve_forever 线程。"""
    return ThreadingHTTPServer((host, port), Handler)


def serve_in_background(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name="lab-server", daemon=True)
    thread.start()
    return thread


def main() -> None:
    server = start_server()
    url = f"http://{HOST}:{PORT}/"
    print(f"SQLiScope 本地靶场已启动：{url}")
    print("按 Ctrl+C 停止")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
