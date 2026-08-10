#!/usr/bin/env python3
# 将 OWASP CRS（Core Rule Set）请求阶段规则转译为 openresty-waf 引擎 DSL 种子。
#
# 用法: python3 scripts/crs_to_seed.py [CRS 规则目录] [输出 Go 文件]
#   默认: /tmp/crs/rules -> admin/internal/model/seed_crs.go
#
# 转译范围：phase 1/2、纯字符串/正则/语义运算符的规则；跳过依赖
# ModSecurity 特性（chain / setvar 状态 / 协议变量）的规则。
import re
import sys
import os

CRS_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/crs/rules"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "admin/internal/model/seed_crs.go")

# 攻击族 -> group 映射（按 CRS 文件编号）
GROUP_MAP = {
    "REQUEST-901": "protocol", "REQUEST-905": "protocol",
    "REQUEST-911": "protocol", "REQUEST-913": "scanner",
    "REQUEST-920": "protocol", "REQUEST-921": "protocol", "REQUEST-922": "protocol",
    "REQUEST-930": "lfi", "REQUEST-931": "lfi",
    "REQUEST-932": "rce", "REQUEST-933": "rce", "REQUEST-934": "rce",
    "REQUEST-941": "xss", "REQUEST-942": "sqli", "REQUEST-943": "protocol",
    "REQUEST-944": "rce", "REQUEST-949": "custom",
}

SEV = {"EMERGENCY": 4, "ALERT": 4, "CRITICAL": 3, "ERROR": 3,
       "WARNING": 2, "NOTICE": 1, "INFO": 0}

OP_MAP = {
    "@rx": "REGEX", "@pm": "PM", "@streq": "EQUALS", "@contains": "CONTAINS",
    "@beginsWith": "STARTS_WITH", "@endsWith": "ENDS_WITH",
    "@detectSQLi": "LIBINJECTION_SQLI", "@detectXSS": "LIBINJECTION_XSS",
}

TRANS_MAP = {
    "lowercase": "to_lowercase",
    "urlDecode": "url_decode", "urlDecodeUni": "url_decode",
    "removeComments": "remove_comments",
    "compressWhitespace": "compress_whitespace",
    "normalizePath": "normalize_path", "normalizePathWin": "normalize_path",
}

RULE_RE = re.compile(
    r'SecRule\s+([^\s"\']+)\s+'  # VAR
    r'("(?:[^"\\]|\\.)*")\s+'   # 运算符+参数 引号（如 "@rx (?i:...)"）
    r'("(?:[^"\\]|\\.)*")',       # actions 引号
    re.DOTALL)


def parse_vars(var_str):
    """返回 (vars_json, parse_keys) 或 None（不支持）"""
    out = []
    for p in var_str.split("|"):
        p = p.strip()
        if p.startswith("REQUEST_HEADERS"):
            spec = p.split(":", 1)[1].strip() if ":" in p else ""
            out.append({"type": "HEADERS", "specific": spec})
        elif p in ("REQUEST_URI", "REQUEST_LINE", "REQUEST_FILENAME"):
            out.append({"type": "REQUEST_URI"})
        elif p == "ARGS":
            out.append({"type": "URI_ARGS"})
            out.append({"type": "POST_ARGS"})
        elif p == "ARGS_NAMES":
            out.append({"type": "URI_ARGS", "parse": ["keys"]})
            out.append({"type": "POST_ARGS", "parse": ["keys"]})
        elif p == "REQUEST_COOKIES":
            out.append({"type": "COOKIE"})
        elif p == "REQUEST_BODY":
            out.append({"type": "BODY"})
        elif p == "REQUEST_COOKIES_NAMES":
            out.append({"type": "COOKIE", "parse": ["keys"]})
        elif p == "REQUEST_HEADERS_NAMES":
            out.append({"type": "HEADERS", "parse": ["keys"]})
        elif p.startswith("XML:") or p.startswith("REQUEST_BODY_JSON") or p == "REQUEST_BODY_JSON":
            continue  # XML/JSON body 专项变量，忽略
        else:
            return None  # TX:、RESPONSE_* 等不支持
    return out if out else None


def parse_transforms(tokens):
    out = []
    for t in tokens:
        t = t.strip()
        if t == "none":
            return []
        m = TRANS_MAP.get(t)
        if m and m not in out:
            out.append(m)
    return out


def extract_actions(actions_str):
    """从 actions 引号串提取 id/phase/block/t/msg/severity/chain"""
    a = {"id": None, "phase": None, "block": False, "t": [], "msg": "",
         "severity": 2, "chain": False}
    m = re.search(r'id:(\d+)', actions_str)
    if m:
        a["id"] = m.group(1)
    m = re.search(r'phase:(\d+)', actions_str)
    if m:
        a["phase"] = int(m.group(1))
    if re.search(r'\bblock\b', actions_str):
        a["block"] = True
    if re.search(r'\bchain\b', actions_str):
        a["chain"] = True
    for m in re.finditer(r't:([a-zA-Z,]+)', actions_str):
        a["t"] += m.group(1).split(",")
    m = re.search(r"msg:'((?:[^'\\]|\\.)*)'", actions_str)
    if m:
        a["msg"] = m.group(1).replace("\\'", "'").replace('\\"', '"')
    m = re.search(r"severity:'(\w+)'", actions_str)
    if m and m.group(1).upper() in SEV:
        a["severity"] = SEV[m.group(1).upper()]
    return a


def go_quote_json(obj):
    """JSON 对象 -> Go 双引号字符串（字段为 string，存 JSON 文本）"""
    import json
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def go_string(s):
    # 优先 Go raw string（反引号），含反引号时用转义字符串
    if "`" not in s:
        return "`" + s + "`"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def split_op_arg(op_arg_str):
    """拆分 '"@rx (?i:...)"' -> ('@rx', '(?i:...)') 或 ('@detectSQLi', '')"""
    inner = op_arg_str[1:-1].strip()
    m = re.match(r'@(\w+)(?:\s+(.*))?$', inner, re.S)
    if not m:
        return None, None
    return '@' + m.group(1), (m.group(2) or '').strip()


def convert_file(path):
    """解析单个 .conf 文件，返回可转译规则列表"""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    # 合并续行
    text = re.sub(r'\\\r?\n\s*', '', text)

    rules = []
    for m in RULE_RE.finditer(text):
        var_str, op_arg_str, actions_str = m.groups()
        if "TX:" in var_str:
            continue
        actions = extract_actions(actions_str)
        if actions["id"] is None or actions["phase"] not in (1, 2):
            continue
        if actions["chain"]:
            continue  # 链式规则依赖顺序，跳过
        op, pattern = split_op_arg(op_arg_str)
        # @pmFromFile：读取同目录 .data 文件转为 PM 词组
        if op == "@pmFromFile" and pattern:
            data_file = os.path.join(os.path.dirname(path), pattern)
            if os.path.isfile(data_file):
                words = []
                with open(data_file, encoding="utf-8", errors="replace") as df:
                    for line in df:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            words.append(line)
                if words:
                    operator = "PM"
                    pattern = "|".join(words)
                else:
                    continue
            else:
                continue
        else:
            operator = OP_MAP.get(op)
            if operator is None:
                continue
        if operator not in ("LIBINJECTION_SQLI", "LIBINJECTION_XSS"):
            if not pattern:
                continue
        vars_list = parse_vars(var_str)
        if vars_list is None:
            continue
        transforms = parse_transforms(actions["t"])
        rules.append({
            "id": actions["id"], "msg": actions["msg"] or ("CRS " + actions["id"]),
            "operator": operator, "pattern": pattern,
            "transforms": transforms, "vars": vars_list,
            "severity": actions["severity"], "block": actions["block"],
        })
    return rules


def main():
    all_rules = []
    files = sorted(f for f in os.listdir(CRS_DIR)
                   if f.startswith("REQUEST-") and f.endswith(".conf"))
    for fn in files:
        base = fn.split("-", 2)[0] + "-" + fn.split("-", 2)[1]
        group = GROUP_MAP.get(fn.rsplit("-", 1)[0].rsplit(".", 1)[0]
                              if False else fn.split("-")[0] + "-" + fn.split("-")[1],
                              "custom")
        # group 由文件名前缀 REQUEST-xxx 决定
        m = re.match(r"(REQUEST-\d+)", fn)
        group = GROUP_MAP.get(m.group(1), "custom")
        for r in convert_file(os.path.join(CRS_DIR, fn)):
            r["group"] = group
            all_rules.append(r)

    # 输出 Go 文件
    lines = []
    lines.append("package model")
    lines.append("")
    lines.append("// Code generated by scripts/crs_to_seed.py — OWASP CRS 请求阶段规则转译（勿手改）")
    lines.append("// 来源: OWASP ModSecurity Core Rule Set (CRS), Apache-2.0 License")
    lines.append("// 仅转译可被引擎执行的部分（phase 1/2, 正则/字符串/语义运算符）")
    lines.append("")
    lines.append("// SeedRulesCRS OWASP CRS 转译的内置规则种子")
    lines.append("var SeedRulesCRS = []Rule{")
    for i, r in enumerate(all_rules):
        actions = {"disrupt": "BLOCK", "status": 403, "msg": r["msg"]}
        status = "403"
        if not r["block"]:
            actions["disrupt"] = "LOG_ONLY"
            status = "0"
        lines.append("\t{RuleID: %s, Name: %s, Group: %s, Phase: \"access\", Severity: %d, Enabled: true," %
                     (go_string(r["id"]), go_string(r["msg"]), go_string(r["group"]), r["severity"]))
        lines.append("\t\tOperator: %s, Pattern: %s," %
                     (go_string(r["operator"]), go_string(r["pattern"])))
        lines.append("\t\tTransforms: %s, Vars: %s," %
                     (go_quote_json(r["transforms"]), go_quote_json(r["vars"])))
        lines.append("\t\tActions: %s, Status: %s, Message: %s, SortOrder: %d}," %
                     (go_quote_json(actions), status, go_string(r["msg"]), i))
    lines.append("}")
    lines.append("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"已生成 {OUT}: {len(all_rules)} 条规则")
    from collections import Counter
    print("分组:", dict(Counter(r["group"] for r in all_rules)))


if __name__ == "__main__":
    main()
