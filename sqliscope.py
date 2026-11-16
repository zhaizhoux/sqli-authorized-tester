# -*- coding: utf-8 -*-
"""SQLiScope — 授权范围内的 SQL 注入自检工具（Windows 桌面版）。

启动后会先弹出法律声明，用户确认后才进入主界面。
所有对外请求都受 core.guard 的授权校验与限速/限量约束。
"""
from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core import engine, guard, payloads
from lab import lab_server

APP_NAME = "SQLiScope"
APP_VERSION = "1.0.0"
DEFAULT_URL = f"http://{lab_server.HOST}:{lab_server.PORT}/search"

DISCLAIMER = (
    "SQLiScope 仅用于对【本人所有】或【已取得所有者书面授权】的系统进行安全自检，"
    "以及在本机内置靶场中做教学演示。\n\n"
    "未经授权对他人系统进行测试、扫描或注入，可能违反《中华人民共和国网络安全法》"
    "《中华人民共和国刑法》等相关法律法规，由此产生的一切后果由使用者自行承担。\n\n"
    "本工具的刻意限制：\n"
    "  · 单目标、限速、限量；不支持批量目标\n"
    "  · 只做注入点探测，不提取数据、不枚举库表、不绕过 WAF\n"
    "  · 公网 / 内网目标需额外输入确认语\n"
    "  · 结论均为「疑似」，必须人工复核\n\n"
    "点击「确定」表示你已阅读并同意上述条款。"
)

TAB_GUIDE_TITLE = "检测原理与修复建议"


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION} · 授权范围内 SQL 注入自检工具")
        self.root.geometry("1120x760")
        self.root.minsize(960, 660)

        self._queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._lab: lab_server.ThreadingHTTPServer | None = None
        self._lab_thread: threading.Thread | None = None
        self._report: dict | None = None
        self._findings: list[dict] = []
        self._running = False

        self._init_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain_queue)
        self._update_zone()
        self.root.after(200, self._show_disclaimer)

    # ---------------------------------------------------------------- 样式
    def _init_style(self) -> None:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", background="#f5f7fa", foreground="#1f2937",
                        font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background="#f5f7fa")
        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f5f7fa")
        style.configure("Card.TLabel", background="#ffffff")
        style.configure("Title.TLabel", background="#f5f7fa", foreground="#1d4ed8",
                        font=("Microsoft YaHei UI", 16, "bold"))
        style.configure("Sub.TLabel", background="#f5f7fa", foreground="#6b7280")
        style.configure("Warn.TLabel", background="#fff7ed", foreground="#9a3412")
        style.configure("TLabelframe", background="#ffffff", bordercolor="#e5e7eb")
        style.configure("TLabelframe.Label", background="#ffffff", foreground="#374151",
                        font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TButton", padding=(10, 6))
        style.configure("Accent.TButton", background="#2563eb", foreground="#ffffff",
                        padding=(14, 7), font=("Microsoft YaHei UI", 10, "bold"))
        style.map("Accent.TButton",
                  background=[("active", "#1d4ed8"), ("disabled", "#93c5fd")])
        style.configure("TNotebook", background="#f5f7fa")
        style.configure("TNotebook.Tab", padding=(16, 8))
        style.configure("Treeview", rowheight=26, background="#ffffff",
                        fieldbackground="#ffffff", foreground="#1f2937")
        style.configure("Treeview.Heading", background="#e8eefc", foreground="#1e3a8a",
                        font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Horizontal.TProgressbar", troughcolor="#e5e7eb",
                        background="#2563eb")

    # ---------------------------------------------------------------- 界面
    def _build_ui(self) -> None:
        header = ttk.Frame(self.root, padding=(18, 12, 18, 6))
        header.pack(fill="x")
        ttk.Label(header, text=f"{APP_NAME} · SQL 注入授权自检", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="单目标 · 限速限量 · 仅探测注入点 · 结论需人工复核",
            style="Sub.TLabel",
        ).pack(anchor="w")

        self.nb = ttk.Notebook(self.root, padding=(14, 6, 14, 12))
        self.nb.pack(fill="both", expand=True)
        self.nb.add(self._build_scan_tab(), text="  检测  ")
        self.nb.add(self._build_guide_tab(), text="  原理与防御  ")
        self.nb.add(self._build_about_tab(), text="  声明与关于  ")

        statusbar = ttk.Frame(self.root, padding=(18, 4, 18, 10))
        statusbar.pack(fill="x")
        self.var_status = tk.StringVar(value="就绪 · 尚未开始检测")
        ttk.Label(statusbar, textvariable=self.var_status, style="Sub.TLabel").pack(side="left")

    def _build_scan_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=8)

        # ---- 授权区 ----
        auth = ttk.LabelFrame(tab, text=" ① 授权确认（必填） ", padding=12)
        auth.pack(fill="x", pady=(0, 8))
        self.var_ack = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            auth,
            text="我确认：目标是本人所有的系统 / 已获所有者书面授权的系统 / 本机内置靶场",
            variable=self.var_ack,
            command=self._update_zone,
        ).pack(anchor="w")
        row = ttk.Frame(auth, padding=(0, 8, 0, 0))
        row.pack(fill="x")
        ttk.Label(row, text="目标归属：").pack(side="left")
        self.var_zone = tk.StringVar(value="—")
        ttk.Label(row, textvariable=self.var_zone, style="Card.TLabel").pack(side="left")
        ttk.Label(row, text="    非回环目标需输入确认语：").pack(side="left")
        ttk.Label(row, text=f"「{guard.CONFIRM_PHRASE}」", foreground="#b91c1c").pack(side="left")
        self.var_phrase = tk.StringVar()
        ttk.Entry(row, textvariable=self.var_phrase, width=24).pack(side="left", padx=6)

        # ---- 目标配置 ----
        cfg = ttk.LabelFrame(tab, text=" ② 目标配置 ", padding=12)
        cfg.pack(fill="x", pady=(0, 8))
        self.var_url = tk.StringVar(value=DEFAULT_URL)
        self.var_param = tk.StringVar(value="id")
        self.var_method = tk.StringVar(value="GET")
        self.var_extra = tk.StringVar(value="")
        self.var_delay = tk.StringVar(value="1.0")
        self.var_timeout = tk.StringVar(value="6")

        line1 = ttk.Frame(cfg)
        line1.pack(fill="x", pady=3)
        ttk.Label(line1, text="目标 URL", width=10).pack(side="left")
        url_entry = ttk.Entry(line1, textvariable=self.var_url)
        url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        url_entry.bind("<KeyRelease>", lambda _e: self._update_zone())
        ttk.Label(line1, text="参数名").pack(side="left")
        ttk.Entry(line1, textvariable=self.var_param, width=10).pack(side="left", padx=6)
        ttk.Label(line1, text="方法").pack(side="left")
        ttk.Combobox(line1, textvariable=self.var_method, values=["GET", "POST"],
                     width=6, state="readonly").pack(side="left", padx=6)

        line2 = ttk.Frame(cfg)
        line2.pack(fill="x", pady=3)
        ttk.Label(line2, text="附加参数", width=10).pack(side="left")
        ttk.Entry(line2, textvariable=self.var_extra).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Label(line2, text="格式 page=1,lang=zh", style="Sub.TLabel").pack(side="left")
        ttk.Label(line2, text="  间隔(s)").pack(side="left")
        ttk.Entry(line2, textvariable=self.var_delay, width=6).pack(side="left", padx=4)
        ttk.Label(line2, text="超时(s)").pack(side="left")
        ttk.Entry(line2, textvariable=self.var_timeout, width=6).pack(side="left", padx=4)

        line3 = ttk.Frame(cfg)
        line3.pack(fill="x", pady=(8, 0))
        ttk.Label(line3, text="检测模式：").pack(side="left")
        self.var_modes = {
            "error": tk.BooleanVar(value=True),
            "boolean": tk.BooleanVar(value=True),
            "time": tk.BooleanVar(value=True),
        }
        for key, label in (("error", "报错型"), ("boolean", "布尔盲注"), ("time", "时间盲注")):
            ttk.Checkbutton(line3, text=label, variable=self.var_modes[key]).pack(side="left", padx=(0, 14))

        # ---- 操作区 ----
        ops = ttk.Frame(tab, padding=(0, 2, 0, 8))
        ops.pack(fill="x")
        ttk.Button(ops, text="启动内置靶场", command=self._start_lab).pack(side="left", padx=(0, 6))
        ttk.Button(ops, text="打开靶场页面", command=self._open_lab).pack(side="left", padx=(0, 16))
        self.btn_start = ttk.Button(ops, text="开始检测", style="Accent.TButton", command=self._on_start)
        self.btn_start.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(ops, text="停止", command=self._on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 6))
        ttk.Button(ops, text="导出报告", command=self._export_report).pack(side="left", padx=(0, 6))
        ttk.Button(ops, text="清空结果", command=self._clear).pack(side="left")
        self.var_verdict = tk.StringVar(value="结论：—")
        ttk.Label(ops, textvariable=self.var_verdict, foreground="#1d4ed8",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(side="right")

        self.pbar = ttk.Progressbar(tab, mode="determinate", maximum=100)
        self.pbar.pack(fill="x", pady=(0, 8))

        # ---- 结果 + 日志 ----
        paned = ttk.PanedWindow(tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        result_frame = ttk.Frame(paned, padding=(0, 0, 0, 4))
        cols = ("no", "category", "payload", "confidence", "evidence")
        self.tree = ttk.Treeview(result_frame, columns=cols, show="headings", height=8)
        for col, title, width in (
            ("no", "#", 44),
            ("category", "类型", 90),
            ("payload", "载荷 / 对比组", 330),
            ("confidence", "置信度", 76),
            ("evidence", "依据", 420),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        vsb = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        paned.add(result_frame, weight=3)

        log_frame = ttk.LabelFrame(paned, text=" 运行日志 ", padding=4)
        self.log = scrolledtext.ScrolledText(log_frame, height=9, wrap="word",
                                             font=("Consolas", 9), bg="#ffffff",
                                             fg="#374151", relief="flat")
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("warn", foreground="#b45309")
        self.log.tag_config("error", foreground="#b91c1c")
        self.log.tag_config("ok", foreground="#15803d")
        self.log.configure(state="disabled")
        paned.add(log_frame, weight=2)
        return tab

    def _build_guide_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=12)
        text = scrolledtext.ScrolledText(tab, wrap="word", font=("Microsoft YaHei UI", 10),
                                         bg="#ffffff", fg="#1f2937", relief="flat", padx=16, pady=14)
        text.pack(fill="both", expand=True)
        lines = [
            "检测原理\n" + "=" * 60,
            "\n本工具只回答一个问题：某个参数的值，有没有可能被直接拼接进 SQL 语句。\n"
            "它不会读取业务数据，也不会尝试枚举库表。\n",
            "\n【1】报错型（Error-based）\n" + "-" * 60,
            "向参数中插入引号、注释符等会破坏 SQL 语法的字符，观察响应里是否出现数据库原始报错。"
            "若基线响应本来就有相同文案，则不计为证据。\n",
        ]
        for item in payloads.ERROR_PAYLOADS:
            lines.append(f"  · {item.value:<38} {item.note}")
        lines += [
            "\n【2】布尔盲注（Boolean-based blind）\n" + "-" * 60,
            "成对发送「永真条件」与「永假条件」，比较两次响应的相似度与长度。"
            "只有当永真响应更接近正常基线、且与永假响应存在明显差异时，才记为线索。"
            "业务本身造成的差异可能带来误报，必须人工复核。\n",
        ]
        for pair in payloads.BOOLEAN_PAIRS:
            lines.append(f"  · {pair.true_payload.value:<24} ⟷ {pair.false_payload.value:<24} {pair.note}")
        lines += [
            "\n【3】时间盲注（Time-based blind）\n" + "-" * 60,
            "发送带延时函数的载荷，若响应明显变慢，再用一次正常请求复核以排除网络抖动。\n",
        ]
        for item in payloads.TIME_PAYLOADS:
            lines.append(f"  · {item.value:<34} {item.note}（{item.dialect}）")
        lines += [
            "\n\n修复建议\n" + "=" * 60,
        ]
        for i, (title, detail) in enumerate(payloads.DEFENSE_TIPS, 1):
            lines.append(f"\n{i}. {title}\n   {detail}")
        lines += [
            "\n\n本地靶场对比\n" + "=" * 60,
            "\n点击「启动内置靶场」后，用同一个参数分别测试：\n"
            f"  http://{lab_server.HOST}:{lab_server.PORT}/search   ← 字符串拼接，有漏洞\n"
            f"  http://{lab_server.HOST}:{lab_server.PORT}/safe     ← 参数化查询，已修复\n"
            "两者返回结构相同，但只有前者会被探测出注入点。\n",
        ]
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")
        return tab

    def _build_about_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=12)
        text = scrolledtext.ScrolledText(tab, wrap="word", font=("Microsoft YaHei UI", 10),
                                         bg="#ffffff", fg="#1f2937", relief="flat", padx=16, pady=14)
        text.pack(fill="both", expand=True)
        body = (
            f"{APP_NAME} {APP_VERSION}\n"
            "=" * 60 + "\n\n"
            "一个用于「授权范围内安全自检」与「安全教学」的 Windows 桌面小工具。\n\n"
            "法律声明\n" + "-" * 60 + "\n" + DISCLAIMER + "\n\n"
            "能力边界\n" + "-" * 60 + "\n"
            "  · 单目标检测，不支持批量 URL 列表\n"
            "  · 请求最小间隔 1 秒，单次任务最多 40 次请求\n"
            "  · 只做注入点探测；不含拖库、库表枚举、凭据提取、WAF 绕过\n"
            "  · 公网 / 内网目标需额外输入确认语\n"
            "  · 所有结论均为初步筛查，不替代代码审计与完整渗透测试\n\n"
            "免责说明\n" + "-" * 60 + "\n" + payloads.DISCLAIMER_SHORT + "\n\n"
            "技术栈\n" + "-" * 60 + "\n"
            "Python 3.12 · tkinter · requests · PyInstaller（单文件 exe）\n"
            "内置靶场使用内存 SQLite，不写磁盘、不联网、只监听 127.0.0.1。\n"
        )
        text.insert("1.0", body)
        text.configure(state="disabled")
        return tab

    # ---------------------------------------------------------------- 交互
    def _show_disclaimer(self) -> None:
        ok = messagebox.askokcancel(
            "使用前必须确认 · 授权与法律声明",
            DISCLAIMER,
            icon="warning",
            parent=self.root,
        )
        if not ok:
            self.root.destroy()
            return
        self._log("已确认授权声明。建议先点击「启动内置靶场」，用本机靶场熟悉流程。", "ok")

    def _update_zone(self) -> None:
        try:
            info = guard.inspect_url(self.var_url.get())
            need = "" if info.zone == "loopback" else f" · 需输入「{guard.CONFIRM_PHRASE}」"
            self.var_zone.set(f"{info.zone_label}{need}")
        except guard.GuardError as exc:
            self.var_zone.set(f"URL 无效：{exc}")

    def _log(self, text: str, level: str = "info") -> None:
        self.log.configure(state="normal")
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{stamp}] {text}\n", level)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear(self) -> None:
        if self._running:
            messagebox.showinfo("提示", "检测进行中，请先停止")
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._findings.clear()
        self._report = None
        self.var_verdict.set("结论：—")
        self.pbar["value"] = 0
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _start_lab(self) -> None:
        if self._lab is not None:
            messagebox.showinfo("内置靶场", f"靶场已在运行：http://{lab_server.HOST}:{lab_server.PORT}/")
            return
        try:
            self._lab = lab_server.start_server()
            self._lab_thread = lab_server.serve_in_background(self._lab)
        except OSError as exc:
            self._lab = None
            messagebox.showerror("启动失败", f"端口 {lab_server.PORT} 可能已被占用：{exc}")
            return
        self.var_url.set(DEFAULT_URL)
        self._update_zone()
        self._log(f"内置靶场已启动：http://{lab_server.HOST}:{lab_server.PORT}/ （仅本机可访问）", "ok")

    def _open_lab(self) -> None:
        if self._lab is None:
            self._start_lab()
        if self._lab is not None:
            webbrowser.open(f"http://{lab_server.HOST}:{lab_server.PORT}/")

    # ---------------------------------------------------------------- 检测
    def _parse_extra(self, raw: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for chunk in raw.replace("，", ",").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" not in chunk:
                raise ValueError(f"附加参数格式错误：{chunk}（应为 key=value）")
            key, value = chunk.split("=", 1)
            result[key.strip()] = value.strip()
        return result

    def _on_start(self) -> None:
        if self._running:
            return
        try:
            info = guard.inspect_url(self.var_url.get())
            guard.verify_authorization(info, self.var_ack.get(), self.var_phrase.get())
            param = self.var_param.get().strip()
            if not param:
                raise guard.GuardError("请填写参数名")
            extra = self._parse_extra(self.var_extra.get())
            delay = max(1.0, float(self.var_delay.get()))
            timeout = max(2.0, min(15.0, float(self.var_timeout.get())))
        except guard.GuardError as exc:
            messagebox.showerror("授权校验未通过", str(exc))
            return
        except ValueError as exc:
            messagebox.showerror("配置有误", str(exc))
            return

        modes = tuple(k for k, var in self.var_modes.items() if var.get())
        if not modes:
            messagebox.showinfo("提示", "请至少勾选一种检测模式")
            return
        if info.zone != "loopback" and not messagebox.askyesno(
            "再次确认",
            f"目标属于【{info.zone_label}】。\n\n请再次确认你持有该系统所有者的书面授权，"
            "且本次测试在授权的时间与范围内进行。",
            icon="warning",
        ):
            return

        self._clear()
        cfg = engine.Config(
            url=info.url,
            param=param,
            method=self.var_method.get(),
            extra_params=extra,
            modes=modes,
            limits=guard.SafetyLimits(
                min_interval=delay, timeout=timeout, max_requests=40
            ),
        )
        self._stop.clear()
        self._running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.var_status.set(f"检测中 · 目标 {info.host} · 限速 {delay}s/次")
        self._worker = threading.Thread(target=self._scan_worker, args=(cfg,), daemon=True)
        self._worker.start()

    def _scan_worker(self, cfg: engine.Config) -> None:
        def emit(kind: str, data: dict) -> None:
            self._queue.put((kind, data))

        try:
            engine.Scanner(cfg, emit, self._stop).run()
        except Exception as exc:  # noqa: BLE001 - 工作线程异常必须回传界面
            emit("error", {"text": f"{type(exc).__name__}: {exc}"})

    def _on_stop(self) -> None:
        if self._running:
            self._stop.set()
            self.var_status.set("正在停止…")

    def _set_finished(self) -> None:
        self._running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, data = self._queue.get_nowait()
                if kind == "log":
                    self._log(data["text"], data.get("level", "info"))
                elif kind == "progress":
                    self.pbar["maximum"] = max(1, data["max"])
                    self.pbar["value"] = data["value"]
                    self.var_status.set(f"检测中 · {data['text']}（{data['value']}/{data['max']}）")
                elif kind == "finding":
                    self._findings.append(data)
                    self.tree.insert(
                        "", "end",
                        values=(
                            len(self._findings),
                            data["category"],
                            data["payload"],
                            data["confidence"],
                            data["evidence"],
                        ),
                    )
                elif kind == "done":
                    self._report = data
                    self.var_verdict.set(f"结论：{data['verdict']}")
                    self.var_status.set(
                        f"完成 · {data['request_count']} 次请求 · {len(data['findings'])} 条线索"
                    )
                    self._log(f"检测完成，共 {data['request_count']} 次请求。", "ok")
                    self._set_finished()
                elif kind == "aborted":
                    self._log(data["text"], "warn")
                    self.var_status.set("已停止")
                    self._set_finished()
                elif kind == "error":
                    self._log(data["text"], "error")
                    self.var_status.set("检测出错")
                    messagebox.showerror("检测出错", data["text"])
                    self._set_finished()
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    # ---------------------------------------------------------------- 报告
    def _export_report(self) -> None:
        if self._report is None:
            messagebox.showinfo("提示", "尚无检测报告，请先完成一次检测")
            return
        path = filedialog.asksaveasfilename(
            title="导出检测报告",
            defaultextension=".json",
            initialfile=f"SQLiScope_报告_{datetime.now():%Y%m%d_%H%M%S}",
            filetypes=[("JSON 报告", "*.json"), ("文本报告", "*.txt")],
        )
        if not path:
            return
        target = Path(path)
        try:
            if target.suffix.lower() == ".txt":
                lines = [
                    f"{APP_NAME} {APP_VERSION} · 授权范围内 SQL 注入自检报告",
                    "=" * 64,
                    f"目标：{self._report['target']}",
                    f"参数：{self._report['param']}    方法：{self._report['method']}",
                    f"模式：{', '.join(self._report['modes'])}",
                    f"开始：{self._report['started']}   结束：{self._report['finished']}",
                    f"请求总数：{self._report['request_count']}",
                    f"结论：{self._report['verdict']}",
                    "", "发现明细", "-" * 64,
                ]
                for i, f in enumerate(self._report["findings"], 1):
                    lines += [
                        f"{i}. [{f['category']}] 置信度 {f['confidence']}",
                        f"   载荷：{f['payload']}",
                        f"   依据：{f['evidence']}",
                        f"   说明：{f['note']}", "",
                    ]
                lines += ["修复建议", "-" * 64]
                lines += [f"{i}. {t['title']}\n   {t['detail']}"
                          for i, t in enumerate(self._report["defense_tips"], 1)]
                lines += ["", "声明", "-" * 64, self._report["disclaimer"]]
                target.write_text("\n".join(lines), encoding="utf-8")
            else:
                target.write_text(
                    json.dumps(self._report, ensure_ascii=False, indent=2), encoding="utf-8"
                )
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self._log(f"报告已导出：{target}", "ok")
        messagebox.showinfo("导出成功", f"报告已保存到：\n{target}")

    def _on_close(self) -> None:
        if self._running:
            if not messagebox.askyesno("确认退出", "检测仍在进行，确定要停止并退出吗？"):
                return
            self._stop.set()
        if self._lab is not None:
            try:
                self._lab.shutdown()
                self._lab.server_close()
            except Exception:  # noqa: BLE001
                pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
