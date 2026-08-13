<script setup lang="ts">
import { NCard, NCode, NTag } from 'naive-ui';

const nginxConfig = `# 在需要防护的 server / location 中加入以下指令
lua_package_path "/opt/waf/?.lua;;";

lua_shared_dict waf_rule    20m;   # 规则缓存/版本
lua_shared_dict waf_counter 50m;   # 频控/统计计数

init_by_lua_file   /opt/waf/init.lua;
access_by_lua_file /opt/waf/access.lua;
log_by_lua_file    /opt/waf/log.lua;`;

const ipRegionNote = `# IP 归属地（可选）
# 将 ip2region_v4.xdb 放入 /opt/waf/ 即可（bind mount 随配置下发）
# 缺失时自动降级：攻击日志不带归属地，不影响防护功能`;

const deployNote = `# 管理后台
# 访问 http://<服务器>:8232 使用 WAF 管理后台（admin / admin123）
# 引擎接入本机 OpenResty，配置变更 5 秒内热更新生效`;
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">接入指引</h2>
      <p class="text-sm text-[rgb(125,125,125)]">将 WAF 引擎挂载到任意 OpenResty 的 server / location</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" title="Nginx 接入配置">
      <NCode :code="nginxConfig" language="nginx" word-wrap />
    </NCard>

    <NCard :bordered="false" class="card-wrapper" title="IP 归属地（可选）">
      <NCode :code="ipRegionNote" language="bash" word-wrap />
    </NCard>

    <NCard :bordered="false" class="card-wrapper" title="部署说明">
      <div class="space-y-2 text-sm">
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>1</NTag>
          <span>将 <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-xs">/opt/waf</code> 目录挂载到 OpenResty 容器或宿主机，加入上述 nginx 配置并 reload</span>
        </div>
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>2</NTag>
          <span>后台「系统配置」可调整防护模式、CRS 偏执级别、豁免路径与日志后端</span>
        </div>
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>3</NTag>
          <span>「规则管理」修改规则后点击「发布到引擎」，5 秒内热更新生效</span>
        </div>
        <NCode :code="deployNote" language="bash" word-wrap />
      </div>
    </NCard>
  </div>
</template>
