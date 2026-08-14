# 慢速攻击与连接层加固

慢速攻击（Slowloris、慢 body、RUDY）在 WAF 引擎层无法完全拦截——
请求头/请求体是 nginx 在进入 Lua 阶段前接收的。本项目采用「引擎规则 + nginx 配置」双层防护。

## 一、nginx 层（推荐必配）

在 `nginx.conf` 的 `http {}` 段加入：

```nginx
# slowloris：请求头读超时（10s 内未读完一个请求头即断开）
client_header_timeout   10s;
# 慢 body / RUDY：两次读 body 之间的超时
client_body_timeout     30s;
# 请求体缓冲上限：超过则落临时文件
# （WAF 上传检测仍会扫描落盘文件前 512KB，见 config.lua upload.spooled_scan_bytes）
client_body_buffer_size 128k;
# 响应发送超时
send_timeout            30s;
```

- `client_header_timeout` 默认 60s，攻击者每 50s 发 1 字节即可长期占满 worker 连接，
  建议收紧到 5~10s。
- `client_body_timeout` 默认 60s，是 RUDY（慢 body）攻击的生存窗口。
- `client_body_buffer_size` 与内存占用正相关，业务有大表单可按需上调；
  超过该值的 body 会落盘，WAF 的上传检测在 `v0.6+` 会流式读取临时文件前
  `spooled_scan_bytes`（默认 512KB）字节继续做后缀/类型检测，不再整体跳过。
- 静态资源站点可在 `location` 内加 `limit_rate 512k;` 防慢读（慢下载拖垮带宽）。

## 二、引擎层（内置规则，默认开启）

内置规则集（`ruleset/builtin.lua`，`builtin-0.6.0`）协议异常组新增：

| 规则 ID | 说明 | 动作 |
|---|---|---|
| 25007 | 请求头数量 ≥100（`HEADERS_COUNT` 变量） | BLOCK 400 |
| 25008 | 请求参数总量 ≥100（`ARGS_COUNT` 变量） | BLOCK 400 |
| 25001-25006 | 原有：非标准方法 / URI 过长 / 方法非法字符 / 异常 Content-Length / 控制字符 | BLOCK |

参数/请求头洪泛属于应用层 DoS，由以上计数规则与 CC 防刷共同覆盖。

## 三、验证

```bash
# 1) 慢请求头：20s 内只发一个字节
(printf 'G'; sleep 20) | timeout 30 nc <host> <port>

# 2) 慢 body：Content-Length 声明大 body 后缓慢发送
printf 'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n' | timeout 60 nc <host> <port>

# 3) 超大上传绕过验证：body 超过 client_body_buffer_size 的上传仍应命中
#    危险后缀拦截（事件列表应出现"文件上传：危险后缀"）
```
