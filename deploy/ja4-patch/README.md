# JA4 nginx 源码补丁（openresty 1.31.1.1 / nginx 1.31.1）

## 背景

OpenResty 的 `ssl_client_hello_by_lua*` 在 nginx 1.25+ 内核上存在兼容问题
（指令可解析但运行时回调不触发）；且 ssl_client_hello 阶段 Lua 无法获取
连接 ID（`ngx.var.connection` → "API disabled"，`ngx.connection()` 不存在），
无法把 JA4 关联到后续请求。

**正解**：直接修改 nginx 源码，在 `ngx_ssl_client_hello_callback` 内计算 JA4，
存入 SSL ex_data，并注册 `$ssl_ja4` 变量——任何阶段可读，与 Lua 无关。

## 补丁内容

两个文件（基于 openresty-1.31.1.1 源码包解压后的 `build/nginx-1.31.1/src/`）：

| 文件 | 修改 |
|---|---|
| `src/event/ngx_event_openssl.c` | ① 顶部声明 `extern int ngx_ssl_ja4_ex_data_index;`<br>② `ngx_ssl_init()` 中（`ngx_ssl_connection_index` 初始化后）增加 `SSL_get_ex_new_index` 初始化（**必须在 OPENSSL_init_ssl 之后，否则返回 -1**）<br>③ 新增 `ngx_ssl_ja4_calc()`：解析 ClientHello（legacy_version + supported_versions 判 TLS1.3、SNI/ALPN、ciphers、extensions）→ 计算 JA4（ja4_a）→ `ngx_pnalloc` 到连接池 → `SSL_set_ex_data`<br>④ `ngx_ssl_client_hello_callback` 的 `done:` 后（`cb->servername()` **之前**）调用 `ngx_ssl_ja4_calc()` |
| `src/http/modules/ngx_http_ssl_module.c` | ① include 后加 `extern int ngx_ssl_ja4_ex_data_index;` + 前置声明 `ngx_ssl_get_ja4()`<br>② 新增 `ngx_ssl_get_ja4()`：从 SSL ex_data 读 JA4<br>③ `ngx_http_ssl_vars[]` 注册 `$ssl_ja4` 变量 |

## 关键坑（踩过的）

1. **`SSL_set_ex_data` 在 ex_data index 未初始化（-1）时会导致握手失败**
   （`SSL_do_handshake() failed: passed invalid argument`）——index 必须
   在 `OPENSSL_init_ssl` 之后初始化，且写入前检查 `index < 0`。
2. **`ngx_pnalloc(c->pool, ...)` 单独使用安全**（连接池在握手阶段可用）。
3. **JA4 计算必须放在 `cb->servername()` 之前**（servername 会切换证书/SSL_CTX，
   之后 OpenSSL client_hello API 行为异常）。
4. OpenSSL 3.5 API：`SSL_client_hello_get0_legacy_version()`（非 get0_version）、
   `SSL_client_hello_get0_ciphers()` 返回**数量**（size_t，每个 cipher 2 字节）。
5. `SSL_CTX_get_client_hello_cb()` 在 OpenSSL 3.5 中**不存在**（无法链式获取
   原回调），故不能以动态模块覆盖回调的方式实现（会破坏 nginx SNI 虚拟主机）。
6. openresty 的 configure 会**自动添加 bundle 模块**，且 `--prefix=/usr/local/openresty`
   会被自动补成 `/usr/local/openresty/nginx`（传全路径会变成 .../nginx/nginx）。
7. 容器 restart 循环排障：bind mount 的 conf.d 文件与容器内操作并发时
   注意原子性（先 stop 再 cp，避免 restart loop 中 exec 失败）。

## 编译步骤（生产容器内）

```bash
# 1. 源码解压（容器内 /tmp）
cd /tmp && tar xzf openresty-1.31.1.1.tar.gz && cd openresty-1.31.1.1

# 2. configure（openresty 自动添加 bundle 模块；prefix 传 /usr/local/openresty）
./configure \
  --prefix=/usr/local/openresty \
  --with-cc-opt="-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include" \
  --with-ld-opt="-Wl,-rpath,/usr/local/openresty/luajit/lib -L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib" \
  --with-pcre --with-compat \
  --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module \
  --with-http_addition_module --with-http_auth_request_module --with-http_dav_module \
  --with-http_flv_module --with-http_geoip_module=dynamic --with-http_gunzip_module \
  --with-http_gzip_static_module --with-http_image_filter_module=dynamic \
  --with-http_mp4_module --with-http_random_index_module --with-http_realip_module \
  --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module \
  --with-http_stub_status_module --with-http_sub_module --with-http_v2_module \
  --with-http_v3_module --with-http_xslt_module=dynamic --with-ipv6 --with-mail \
  --with-mail_ssl_module --with-md5-asm --with-sha1-asm --with-stream \
  --with-stream_ssl_module --with-stream_ssl_preread_module --with-threads \
  --with-pcre-jit --with-stream

# 3. 应用补丁：将本目录两个 .ja4 文件覆盖到
#    build/nginx-1.31.1/src/event/ngx_event_openssl.c
#    build/nginx-1.31.1/src/http/modules/ngx_http_ssl_module.c

# 4. 编译
make -j8

# 5. 替换（先备份）
cp /usr/local/openresty/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx.bak-ja4
cp build/nginx-1.31.1/objs/nginx /usr/local/openresty/nginx/sbin/nginx

# 6. 重启容器（reload 不切换二进制：master 用 /proc/self/exe 的旧版）
#    nginx 启动命令带 -c 指定配置（1Panel 容器直接 restart 即可）
```

## 验证

```bash
# 变量（access 阶段可读）
curl -sk https://<host>/   # $ssl_ja4 形如 t133fc_e02125ef7128_b28b1408f3d9
```

WAF 侧（fingerprint.lua）已支持：`ngx.var.ssl_ja4` 优先（source=ja4），
回退 TLS 变量指纹 / HTTP 指纹。恶意指纹库比对、爬虫记录 ja4 字段均使用真实 JA4。
