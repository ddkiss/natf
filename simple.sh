#!/bin/bash
# 简单的 nftables NAT 管理脚本 (兼容旧版 Bash set -u 逻辑)
# 依赖环境: bash 4.0+, awk, getent, nft
set -euo pipefail

# 默认配置路径
CONFIG_FILE=${1:-/etc/nat.toml}
NFT_SCRIPT="/tmp/apply_nat.nft"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 找不到配置文件 $CONFIG_FILE"
    echo "用法: $0 [配置文件路径]"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "权限错误: 请以 root 身份运行此脚本。"
    exit 1
fi

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
    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $domain =~ ^[0-9a-fA-F:]+$ ]]; then
        echo "$domain"
        return
    fi
    if [ "$v" = "ipv4" ] || [ "$v" = "all" ]; then
        getent ahosts "$domain" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}' || true
    elif [ "$v" = "ipv6" ]; then
        getent ahosts "$domain" 2>/dev/null | awk '$1 ~ /:/ {print $1; exit}' || true
    fi
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
    [ -n "${RULE[type]+set}" ] && type="${RULE[type]//\"/}"
    [ -n "${RULE[sport]+set}" ] && sport="${RULE[sport]//\"/}"
    [ -n "${RULE[dport]+set}" ] && dport="${RULE[dport]//\"/}"
    [ -n "${RULE[domain]+set}" ] && domain="${RULE[domain]//\"/}"
    [ -n "${RULE[protocol]+set}" ] && protocol="${RULE[protocol]//\"/}"
    [ -n "${RULE[ip_version]+set}" ] && ip_version="${RULE[ip_version]//\"/}"
    [ -n "${RULE[port_start]+set}" ] && port_start="${RULE[port_start]//\"/}"
    [ -n "${RULE[port_end]+set}" ] && port_end="${RULE[port_end]//\"/}"
    [ -n "${RULE[sport_end]+set}" ] && sport_end="${RULE[sport_end]//\"/}"
    [ -n "${RULE[chain]+set}" ] && chain="${RULE[chain]//\"/}"
    [ -n "${RULE[src_ip]+set}" ] && src_ip="${RULE[src_ip]//\"/}"
    [ -n "${RULE[dst_port]+set}" ] && dst_port="${RULE[dst_port]//\"/}"
    [ -n "${RULE[dst_port_end]+set}" ] && dst_port_end="${RULE[dst_port_end]//\"/}"
    
    local protos=()
    if [ "$protocol" = "all" ]; then protos=("tcp" "udp"); else protos=("$protocol"); fi
    local versions=()
    if [ "$ip_version" = "all" ]; then versions=("ip" "ip6"); else versions=("$ip_version"); fi

    # 1. 单端口转发
    if [ "$type" = "single" ]; then
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            local daddr=$(resolve_domain "$domain" "$v")
            [ -z "$daddr" ] && continue
            for p in "${protos[@]}"; do
                echo "add rule $nft_v self-nat prerouting $p dport $sport dnat to $daddr:$dport" >> "$NFT_SCRIPT"
            done
        done
        
    # 2. 端口段转发
    elif [ "$type" = "range" ]; then
        for v in "${versions[@]}"; do
            local nft_v="ip"
            [[ "$v" == "ipv6" || "$v" == "ip6" ]] && nft_v="ip6"
            local daddr=$(resolve_domain "$domain" "$v")
            [ -z "$daddr" ] && continue
            for p in "${protos[@]}"; do
                echo "add rule $nft_v self-nat prerouting $p dport $port_start-$port_end dnat to $daddr" >> "$NFT_SCRIPT"
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
                echo "add rule $nft_v self-nat prerouting $p dport $sp redirect to :$dport" >> "$NFT_SCRIPT"
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
            for p in "${protos[@]}"; do
                local port_expr=""
                if [ -n "$dst_port" ]; then
                    if [ -n "$dst_port_end" ]; then port_expr="$p dport $dst_port-$dst_port_end"
                    else port_expr="$p dport $dst_port"; fi
                fi
                echo "add rule $nft_v self-filter $chain $filter_expr $port_expr drop" >> "$NFT_SCRIPT"
            done
        done
    fi
    
    # 彻底清空数组内容，但保留关联数组属性
    RULE=()
}

echo "[*] 正在解析配置文件 $CONFIG_FILE ..."

# 简易 TOML 解析
while IFS= read -r line || [ -n "$line" ]; do
    # 移除注释和前后空格
    line=$(echo "$line" | sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -z "$line" ] && continue
    
    if [[ "$line" == "[[rules]]" ]]; then
        process_rule
        continue
    fi
    
    # 解析 key = value
    if [[ "$line" =~ ^([a-zA-Z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        # 显式使用全局变量赋值
        RULE["$key"]="$val"
    fi
done < "$CONFIG_FILE"

# 处理最后一条规则
process_rule

echo "[*] 生成的 nftables 脚本位于: $NFT_SCRIPT"
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
