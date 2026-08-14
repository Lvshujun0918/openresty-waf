# 部署与测试

## 冒烟测试（Docker）

前置：本机安装 Docker。

```bash
# 1. 启动带 WAF 的 OpenResty 测试实例
docker run -d --rm --name waf-test \
  -p 8080:8080 \
  -v "$PWD/../waf":/waf \
  -v "$PWD/nginx-test.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine

# 2. 准备日志目录
docker exec waf-test mkdir -p /var/log/waf

# 3. 验证
# 正常请求 -> 200
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
# 敏感文件泄露规则 -> 403
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/test.php.bak
# 扫描器 UA 规则 -> 403
curl -s -o /dev/null -w "%{http_code}\n" -A "sqlmap/1.0" http://127.0.0.1:8080/

# 4. 查看攻击日志
docker exec waf-test sh -c 'cat /var/log/waf/*.log'

# 5. 清理
docker rm -f waf-test
```

## 规则热更新端到端测试

验证"管理后台配置规则 → Redis 下发 → OpenResty 引擎热更新生效（无需 reload）"闭环。

前置：宿主运行 Redis（127.0.0.1:6379）与 WAF 管理后台。

```bash
# 1. 启动启用热更新的 OpenResty（--network=host 使容器直连宿主 Redis）
docker run -d --rm --name waf-hotreload --network=host \
  -v "$PWD/../waf":/waf \
  -v "$PWD/nginx-hotreload.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine

# 2. 通过管理后台发布规则（需先登录获取 token）
TOKEN=$(curl -s -X POST http://127.0.0.1:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r .token)

# 3. 等待引擎轮询（默认 5s），用非本机 IP 验证（127.0.0.1 默认在白名单内放行）
HOST_IP=$(hostname -I | awk '{print $1}')
curl -s -o /dev/null -w "%{http_code}\n" "http://$HOST_IP:8080/test.php.bak"  # 403
curl -s -o /dev/null -w "%{http_code}\n" "http://$HOST_IP:8080/?id=1%20union%20select%201"  # 403
```

## 生产接入

在任意 OpenResty 的 `nginx.conf` 中挂载：

```nginx
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule    20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file         /opt/waf/init.lua;
init_worker_by_lua_file  /opt/waf/init.lua;   # 启用 Redis 规则热更新
access_by_lua_file       /opt/waf/access.lua;
log_by_lua_file          /opt/waf/log.lua;
header_filter_by_lua_file /opt/waf/header_filter.lua;   # 响应检测（可选）
body_filter_by_lua_file   /opt/waf/body_filter.lua;     # 响应检测（可选）
```
