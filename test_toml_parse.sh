#!/bin/bash
set -euo pipefail

CONFIG_FILE=${1:-example.toml}

python3 - "$CONFIG_FILE" <<'PY'
import sys

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        print("错误: 需要 Python 3.11+ 自带的 tomllib，或额外安装 tomli。", file=sys.stderr)
        sys.exit(1)

config_path = sys.argv[1]

with open(config_path, "rb") as f:
    data = tomllib.load(f)

rules = data.get("rules")
if not isinstance(rules, list):
    print("错误: 顶层 rules 不是 [[rules]] 数组表。", file=sys.stderr)
    sys.exit(1)

target = None
for rule in rules:
    if rule.get("sport") == 18080:
        target = rule
        break

if target is None:
    print("错误: 未找到 sport = 18080 的回归样例。", file=sys.stderr)
    sys.exit(1)

expected_comment = "回归测试 # 保留字符串内的井号"
if target.get("comment") != expected_comment:
    print("错误: comment 未保留 # 字符。", file=sys.stderr)
    print(f"期望: {expected_comment}", file=sys.stderr)
    print(f"实际: {target.get('comment')!r}", file=sys.stderr)
    sys.exit(1)

if not isinstance(target.get("sport"), int):
    print("错误: sport 没有按 TOML 整数类型解析。", file=sys.stderr)
    sys.exit(1)

print(f"OK: {config_path} 中的 # 字符串解析正常。")
PY
