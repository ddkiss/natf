#!/bin/bash
# 简单的 nftables NAT 管理脚本 (兼容旧版 Bash set -u 逻辑)
# 依赖环境: bash 4.0+, python3 (tomllib/tomli), awk, getent, nft
set -euo pipefail

# 默认配置路径
CONFIG_FILE="/etc/nat.toml"
AUTO_CONFIRM="${NATF_FORCE:-0}"
NFT_SCRIPT=""
PARSED_RULES_FILE=""

cleanup() {
    rm -f "$NFT_SCRIPT" "$PARSED_RULES_FILE"
}

usage() {
    echo "用法: $0 [--yes] [配置文件路径]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --yes)
            AUTO_CONFIRM=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "错误: 不支持的参数 $1"
            usage
            exit 1
            ;;
        *)
            if [ "$CONFIG_FILE" != "/etc/nat.toml" ]; then
                echo "错误: 只能提供一个配置文件路径"
                usage
                exit 1
            fi
            CONFIG_FILE="$1"
            shift
            ;;
    esac
done

if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 找不到配置文件 $CONFIG_FILE"
    usage
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "权限错误: 请以 root 身份运行此脚本。"
    exit 1
fi

umask 077
NFT_SCRIPT=$(mktemp "${TMPDIR:-/tmp}/apply_nat.XXXXXX.nft")
PARSED_RULES_FILE=$(mktemp "${TMPDIR:-/tmp}/parsed_rules.XXXXXX.bin")
trap cleanup EXIT

# 初始化生成的 nftables 规则集
cat > "$NFT_SCRIPT" << 'EOF'
flush ruleset

table ip self-nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname != "lo" masquerade
    }
    chain output {
        type nat hook output priority -100; policy accept;
    }
}

table ip6 self-nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname != "lo" masquerade
    }
    chain output {
        type nat hook output priority -100; policy accept;
    }
}

table ip self-filter {
    chain input {
        type filter hook input priority filter; policy accept;
        ct state established,related accept
        ct state invalid drop
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state established,related accept
        ct state invalid drop
    }
}

table ip6 self-filter {
    chain input {
        type filter hook input priority filter; policy accept;
        ct state established,related accept
        ct state invalid drop
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state established,related accept
        ct state invalid drop
    }
}
EOF

# 简易 DNS 解析函数 (增加 || true 防止 set -e 导致脚本因解析失败退出)
resolve_domain() {
    local domain=$1
    local v=$2
    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $domain =~ ":" ]]; then
        echo "$domain"
        return
    fi
    if [ "$v" = "ipv4" ] || [ "$v" = "all" ] || [ "$v" = "ip" ]; then
        getent ahosts "$domain" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}' || true
    elif [ "$v" = "ipv6" ] || [ "$v" = "ip6" ]; then
        getent ahosts "$domain" 2>/dev/null | awk '$1 ~ /:/ {print $1; exit}' || true
    fi
}

parse_toml_rules() {
    python3 - "$1" <<'PY'
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

try:
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
except tomllib.TOMLDecodeError as exc:
    print(f"错误: TOML 解析失败 ({config_path}:{exc.lineno}:{exc.colno}): {exc.msg}", file=sys.stderr)
    sys.exit(1)
except OSError as exc:
    print(f"错误: 读取配置文件失败 ({config_path}): {exc}", file=sys.stderr)
    sys.exit(1)

rules = data.get("rules")
if rules is None:
    sys.exit(0)
if not isinstance(rules, list):
    print("错误: 顶层字段 rules 必须是数组表 [[rules]]。", file=sys.stderr)
    sys.exit(1)

for index, rule in enumerate(rules, start=1):
    if not isinstance(rule, dict):
        print(f"错误: rules[{index}] 必须是对象。", file=sys.stderr)
        sys.exit(1)

    sys.stdout.buffer.write(b"__RULE__\0")
    for key, value in rule.items():
        if not isinstance(key, str):
            print(f"错误: rules[{index}] 包含非字符串键。", file=sys.stderr)
            sys.exit(1)

        if isinstance(value, bool):
            normalized = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            normalized = str(value)
        else:
            print(
                f"错误: rules[{index}].{key} 的值类型不受支持: {type(value).__name__}",
                file=sys.stderr,
            )
            sys.exit(1)

        sys.stdout.buffer.write(key.encode("utf-8"))
        sys.stdout.buffer.write(b"\0")
        sys.stdout.buffer.write(normalized.encode("utf-8"))
        sys.stdout.buffer.write(b"\0")
PY
}

# 全局声明关联数组
declare -A RULE

# 核心处理组装函数
process_rule() {
    # 核心修复点：通过 set +u 避开旧版 Bash 对空关联数组长度检查的限制
    local len=0
    set +u
    len=${#RULE[@]}
    set -u
    
    if [ "$len" -eq 0 ]; then
        return
    fi
    
    local type="" sport="" dport="" domain="" protocol="all" ip_version="all"
    local port_start="" port_end="" sport_end=""
    local chain="" src_ip="" dst_port="" dst_port_end=""

    # 使用 ${RULE[key]+set} 安全检查键是否存在
    [ -n "${RULE[type]+set}" ] && { type="${RULE[type]#\"}"; type="${type%\"}"; }
    [ -n "${RULE[sport]+set}" ] && { sport="${RULE[sport]#\"}"; sport="${sport%\"}"; }
    [ -n "${RULE[dport]+set}" ] && { dport="${RULE[dport]#\"}"; dport="${dport%\"}"; }
    [ -n "${RULE[domain]+set}" ] && { domain="${RULE[domain]#\"}"; domain="${domain%\"}"; }
    [ -n "${RULE[protocol]+set}" ] && { protocol="${RULE[protocol]#\"}"; protocol="${protocol%\"}"; }
    [ -n "${RULE[ip_version]+set}" ] && { ip_version="${RULE[ip_version]#\"}"; ip_version="${ip_version%\"}"; }
    [ -n "${RULE[port_start]+set}" ] && { port_start="${RULE[port_start]#\"}"; port_start="${port_start%\"}"; }
    [ -n "${RULE[port_end]+set}" ] && { port_end="${RULE[port_end]#\"}"; port_end="${port_end%\"}"; }
    [ -n "${RULE[sport_end]+set}" ] && { sport_end="${RULE[sport_end]#\"}"; sport_end="${sport_end%\"}"; }
    [ -n "${RULE[chain]+set}" ] && { chain="${RULE[chain]#\"}"; chain="${chain%\"}"; }
    [ -n "${RULE[src_ip]+set}" ] && { src_ip="${RULE[src_ip]#\"}"; src_ip="${src_ip%\"}"; }
    [ -n "${RULE[dst_port]+set}" ] && { dst_port="${RULE[dst_port]#\"}"; dst_port="${dst_port%\"}"; }
    [ -n "${RULE[dst_port_end]+set}" ] && { dst_port_end="${RULE[dst_port_end]#\"}"; dst_port_end="${dst_port_end%\"}"; }
    
    local protos=()
    if [ "$protocol" = "all" ]; then protos=("tcp" "udp"); else protos=("$protocol"); fi
    local versions=()
    if [ "$ip_version" = "all" ]; then versions=("ip" "ip6"); else versions=("$ip_version"); fi

    # 1. 单端口转发
    if [ "$type" = "single" ]; then
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            local daddr=$(resolve_domain "$domain" "$nft_v")
            [ -z "$daddr" ] && continue
            if [[ "$daddr" =~ ":" ]] && [ "$nft_v" = "ip" ]; then continue; fi
            if [[ "$daddr" =~ \. ]] && [ "$nft_v" = "ip6" ]; then continue; fi
            for p in "${protos[@]}"; do
                echo "add rule $nft_v self-nat prerouting fib daddr type local $p dport $sport dnat to $daddr:$dport" >> "$NFT_SCRIPT"
            done
        done
        
    # 2. 端口段转发
    elif [ "$type" = "range" ]; then
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            local daddr=$(resolve_domain "$domain" "$nft_v")
            [ -z "$daddr" ] && continue
            if [[ "$daddr" =~ ":" ]] && [ "$nft_v" = "ip" ]; then continue; fi
            if [[ "$daddr" =~ \. ]] && [ "$nft_v" = "ip6" ]; then continue; fi
            for p in "${protos[@]}"; do
                echo "add rule $nft_v self-nat prerouting fib daddr type local $p dport $port_start-$port_end dnat to $daddr" >> "$NFT_SCRIPT"
            done
        done
        
    # 3. 端口重定向
    elif [ "$type" = "redirect" ]; then
        local sp="$sport"
        [ -n "$sport_end" ] && sp="$sport-$sport_end"
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            for p in "${protos[@]}"; do
                echo "add rule $nft_v self-nat prerouting fib daddr type local $p dport $sp redirect to :$dport" >> "$NFT_SCRIPT"
            done
        done
        
    # 4. 过滤丢弃
    elif [ "$type" = "drop" ]; then
        local filter_expr=""
        if [ -n "$src_ip" ]; then
            local prefix="ip"
            [[ "$src_ip" =~ ":" ]] && prefix="ip6"
            filter_expr="$prefix saddr $src_ip"
        fi
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            if [[ "$src_ip" =~ ":" ]] && [ "$nft_v" = "ip" ]; then continue; fi
            if [[ "$src_ip" =~ \. ]] && [ "$nft_v" = "ip6" ]; then continue; fi
            for p in "${protos[@]}"; do
                local port_expr=""
                if [ -n "$dst_port" ]; then
                    if [ -n "$dst_port_end" ]; then port_expr="$p dport $dst_port-$dst_port_end"
                    else port_expr="$p dport $dst_port"; fi
                elif [[ "$p" == "tcp" || "$p" == "udp" ]]; then
                    port_expr="meta l4proto $p"
                fi
                echo "add rule $nft_v self-filter $chain $filter_expr $port_expr drop" >> "$NFT_SCRIPT"
            done
        done
    fi
    
    # 彻底清空数组内容，但保留关联数组属性
    RULE=()
}

echo "[*] 正在解析配置文件 $CONFIG_FILE ..."

if ! parse_toml_rules "$CONFIG_FILE" > "$PARSED_RULES_FILE"; then
    exit 1
fi

while IFS= read -r -d '' item; do
    if [ "$item" = "__RULE__" ]; then
        process_rule
        continue
    fi

    key="$item"
    if ! IFS= read -r -d '' val; then
        echo "错误: 解析后的规则数据不完整。"
        exit 1
    fi
    RULE["$key"]="$val"
done < "$PARSED_RULES_FILE"

# 处理最后一条规则
process_rule

echo "[*] 生成的 nftables 脚本位于: $NFT_SCRIPT"
if [ "$AUTO_CONFIRM" != "1" ]; then
    echo "[!] 即将执行 'flush ruleset'，这会清空当前机器上的全部 nftables 规则。"
    if [ ! -t 0 ]; then
        echo "错误: 当前不是交互式终端。请传入 --yes 或设置 NATF_FORCE=1 后重试。"
        exit 1
    fi
    read -r -p "输入 yes 继续: " confirm
    if [ "$confirm" != "yes" ]; then
        echo "[*] 已取消。"
        exit 1
    fi
fi

echo "[*] 正在预检查 nftables 规则..."
if ! nft -c -f "$NFT_SCRIPT"; then
    echo "========= [失败] ========="
    echo "规则预检查失败，未应用任何变更。请检查配置文件中的格式和错误。"
    exit 1
fi

echo "[*] 正在重置并应用 nftables 规则..."
if nft -f "$NFT_SCRIPT"; then
    echo "========= [成功] ========="
    echo "nftables 规则加载成功！"
    echo "运行 'nft list ruleset' 查看生效的配置。"
else
    echo "========= [失败] ========="
    echo "应用规则失败，请检查配置文件中的格式和错误。"
    exit 1
fi
