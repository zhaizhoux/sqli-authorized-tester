# -*- coding: utf-8 -*-
"""一键打包 Windows 单文件 exe。

用法（在已安装依赖的虚拟环境中）：
    python build.py

产物：dist/SQLiScope.exe
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "SQLiScope",
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build"),
        "--specpath",
        str(ROOT),
        "--exclude-module",
        "pytest",
        "--exclude-module",
        "IPython",
        str(ROOT / "sqliscope.py"),
    ]
    print("执行：", " ".join(cmd))
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print("打包失败")
        return result.returncode
    exe = ROOT / "dist" / "SQLiScope.exe"
    if exe.exists():
        print(f"打包完成：{exe}  ({exe.stat().st_size / 1024 / 1024:.1f} MB)")
    else:
        print("未找到产物，请检查上方日志")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
