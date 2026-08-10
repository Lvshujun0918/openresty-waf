# WAF 性能基准测试

加 WAF 前后性能影响对比。测试日期：2026-08-10。

## 测试环境

| 项 | 值 |
|---|---|
| CPU | 16 核 |
| 内存 | 46 GB |
| OpenResty | 1.31.1.1（Docker，host 网络） |
| 压测工具 | ab（ApacheBench），`-n 50000 -c 100 -k`（keep-alive） |
| 访问地址 | 宿主 IP 非本机回环（避免命中默认白名单 127.0.0.1） |

## 测试方法

三组场景串行压测（避免资源争抢），同一 OpenResty 镜像：

| 场景 | 配置 | 说明 |
|---|---|---|
| 基准（无 WAF） | `deploy/nginx-bench-base.conf` | 纯 `content_by_lua` 返回，无检测 |
| 加 WAF（普通请求） | `deploy/nginx-bench-waf.conf` | 完整检测链路，请求 `/?id=1` 放行 |
| 加 WAF（攻击请求） | `deploy/nginx-bench-waf.conf` | 请求 `/?id=1 union select 1` 命中拦截 + 日志写盘 |

> 说明：压测时**禁用 CC 防刷**（避免高频压测被 CC 判定封禁，掩盖检测开销）；CC 本身的正确性已在单独测试验证（高频请求触发 503 封禁）。

## 测试结果

| 场景 | RPS | 平均延迟 | 相对基准 RPS | 相对基准延迟 |
|---|---|---|---|---|
| 基准（无 WAF） | **179,211** | **0.558 ms** | 100% | 1.0× |
| 加 WAF（普通请求） | 93,789 | 1.066 ms | -47.7% | 1.91× |
| 加 WAF（攻击请求） | 61,423 | 1.628 ms | -65.7% | 2.92× |

- 普通请求：5 万请求全部 200（Failed 0）。
- 攻击请求：5 万请求全部 403 拦截（Non-2xx 50000），命中日志完整写入（5 万行 / 12 MB）。

## 分析

1. **检测开销**：加 WAF 后普通请求吞吐约降一半（-47.7%），平均延迟增加约 0.5ms。
   主要开销来自规则引擎对 URI_ARGS 的提取、URL 解码变换与 22 条规则的 REGEX 匹配。
   单请求检测耗时约 0.5ms，处于开源 WAF 合理区间（lua-resty-waf 官方宣称全规则集 300–500µs，量级一致）。

2. **拦截 + 日志开销**：攻击场景额外下降约 18 个百分点，来自 403 响应构造与日志文件 IO（`io.open` 追加写）。
   生产环境建议将日志后端切换为 `redis`（异步批量上报，不阻塞收尾），可显著降低此开销。

3. **CC 防刷副作用验证**：未禁用 CC 时，单 IP 高频压测被正确判定为 CC 并触发封禁（返回 503），符合设计预期。

## 优化建议（后续）

- 规则引擎：启动时预编译正则并缓存匹配结果（当前 REGEX 走 PCRE JIT，已在途）。
- 日志：`redis` 后端替代 file 直写，或批量合并写盘。
- 检测剪枝：白名单路径、静态资源后缀（.css/.js/.png）跳过 body/args 检测。
- 命中缓存：同一 IP+URI 短期缓存判定结果（参考 CDN WAF 常见做法）。

## 复现

```bash
# 基准
docker run -d --rm --name bench-base --network=host \
  -v "$PWD/deploy/nginx-bench-base.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine
ab -n 50000 -c 100 -k "http://<HOST_IP>:8082/?id=1"

# 加 WAF
docker run -d --rm --name bench-waf --network=host \
  -v "$PWD/waf":/waf \
  -v "$PWD/deploy/nginx-bench-waf.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine
ab -n 50000 -c 100 -k "http://<HOST_IP>:8083/?id=1"
```
