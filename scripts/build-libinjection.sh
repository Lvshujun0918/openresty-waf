#!/bin/sh
# 重新编译 libinjection.so（语义检测，libinjection BSD 许可）
#
# 用法：./scripts/build-libinjection.sh [输出路径]
#
# 默认输出：waf/libinjection/libinjection.so（glibc x86_64，与 1Panel Ubuntu 系 OpenResty 兼容）
# 如需 musl（Alpine 系 OpenResty），在 Alpine 环境中执行本脚本。
#
# 依赖：gcc + make 头文件（无需 SWIG；Lua 侧通过 LuaJIT FFI 直接调用 C API）

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/waf/libinjection/src"
OUT="${1:-$ROOT/waf/libinjection/libinjection.so}"

gcc -O2 -fPIC -shared -o "$OUT" \
    "$SRC/libinjection_sqli.c" \
    "$SRC/libinjection_html5.c" \
    "$SRC/libinjection_xss.c"

echo "已生成 $OUT"
file "$OUT"
