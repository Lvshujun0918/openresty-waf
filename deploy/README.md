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
```
