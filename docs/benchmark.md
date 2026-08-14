# WAF 性能基准测试

加 WAF 前后性能影响对比。最新测试日期：2026-08-14（版本化缓存 + 静态剪枝落地后）。

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
| 加 WAF（攻击请求） | `deploy/nginx-bench-waf.conf` | 请求 `/?id=1%20union%20select%201` 命中拦截 + 日志写盘 |

> 说明：
> - 压测时无后台触发规则（未发布 CC 规则），CC 不会误伤压测；CC 正确性已单独验证。
> - **攻击 payload 必须 URL 编码**：原始空格会触发 nginx 请求行解析的慢路径，吞吐
>   降至约 1/7（实测无 WAF 的裸 nginx 同样如此，与 WAF 无关），会严重污染数据。
> - 基准配置未挂载 `header_filter/body_filter` 响应检测（可选挂载），
>   响应检测开销约为响应体累积 8KB 截断 + EOF 一次规则扫描，实际生产请自行评估。

## 测试结果（2026-08-14，优化后）

| 场景 | RPS | 相对基准 |
|---|---|---|
| 基准（无 WAF） | **181,148** | 100% |
| 加 WAF（普通请求） | **169,169** | **-6.6%** |
| 加 WAF（攻击请求，403 拦截 + 日志） | **148,613** | **-18.0%** |

- 普通请求：5 万请求全部 200（Failed 0）。
- 攻击请求：5 万请求全部 403 拦截（Non-2xx 50000），命中日志完整写入。

## 历史数据与优化历程

| 版本 | 普通请求相对基准 | 攻击请求相对基准 | 关键优化 |
|---|---|---|---|
| 2026-08-10 初版 | -47.7% | -65.7% | 无 |
| 2026-08-10 优化 | -39.9% | - | 请求级变量提取缓存 |
| **2026-08-14 优化** | **-6.6%** | **-18.0%** | 见下方「已落地优化」 |

### 已落地优化（2026-08-14）

- **规则集/生效配置/触发规则集版本化缓存**：原实现每个请求对整份 JSON 规则集
  （后台 CRS 规则数百条）执行 `cjson.decode`，且触发规则集在 access 阶段最多被
  解码 3 次。改为按共享内存版本号（`ruleset_version` / `config_version` /
  `trigger_rules_version`）缓存解码结果，版本未变化时直接复用，热更新链路不变。
- **静态资源剪枝**：图片/字体/JS/CSS 等静态后缀（`config.detection.skip_static`）
  跳过规则引擎检测，名单/CC/人机验证仍生效。
- **拦截动作复用配置缓存**：BLOCK 动作渲染拦截页时不再重复解码配置 JSON，
  复用引擎的版本化配置缓存。

### 方法论修正

- 攻击 payload 改为 URL 编码（`%20`）：原始空格请求在 nginx 请求行解析层即被
  拖慢约 7 倍（用无 WAF 的最小 403 对照组验证，与 WAF 代码无关）。
- 实测日志 file 后端（`io.open` 追加写）在本次环境（OS 页缓存）下对吞吐影响
  可忽略；高并发生产环境仍建议切换 `redis` 后端异步上报。

## 分析

1. **普通请求开销**：加 WAF 后吞吐仅下降约 6.6%，主要来自规则引擎对
   URI_ARGS/HEADERS/BODY 的变量提取与 22 条内置规则的 REGEX 匹配。
   单请求检测耗时约 0.08–0.1ms（base 0.55ms → WAF 0.59ms），优于
   lua-resty-waf 宣称的全规则集 300–500µs。
2. **拦截 + 日志开销**：攻击场景额外下降约 11 个百分点，来自 403 响应构造、
   事件组装与日志写盘；命中即返回，不进入内容阶段。
3. **CC 防刷副作用验证**：未发布触发规则时压测不受 CC 影响；发布 CC 规则后
   单 IP 高频请求会被正确判定封禁（返回 503）。

## 后续可继续的优化方向

- **命中缓存**：同一 IP+URI 短时缓存判定结果（参考 CDN WAF 常见做法），
  进一步收窄攻击场景与高频重复请求的开销。
- **日志异步化**：生产环境切 `redis` 后端，消除攻击场景文件 IO 抖动
  （本地盘/页缓存环境实测影响很小，网络盘/慢盘环境收益明显）。
- **规则集精简**：按命中率排序规则、相同变量规则合并单次扫描，降低
  规则数量增长（后台 CRS 数百条）时的线性开销。

## 复现

```bash
# 基准
cd <repo>
docker run -d --rm --name bench-base --network=host \
  -v "$PWD/deploy/nginx-bench-base.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine
ab -n 50000 -c 100 -k "http://<HOST_IP>:8082/?id=1"

# 加 WAF
docker run -d --rm --name bench-waf --network=host \
  -v "$PWD/waf":/waf \
  -v "$PWD/deploy/nginx-bench-waf.conf":/usr/local/openresty/nginx/conf/nginx.conf \
  openresty/openresty:alpine
# 普通请求
ab -n 50000 -c 100 -k "http://<HOST_IP>:8083/?id=1"
# 攻击请求（payload 必须 URL 编码，见上文方法论说明）
ab -n 50000 -c 100 -k "http://<HOST_IP>:8083/?id=1%20union%20select%201"
```
