<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { NAlert, NButton, NCard, NCode, NSpace, NTag, useMessage } from 'naive-ui';
import { fetchSetupGuide } from '@/service/api';

interface SetupGuide {
  redis: { addr: string; password: string; db: number };
  install_command: string;
  download_url: string;
  nginx_config: string;
}

const message = useMessage();
const guide = ref<SetupGuide | null>(null);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const res = await fetchSetupGuide();
    guide.value = res.data ?? null;
  } finally {
    loading.value = false;
  }
}

async function copyInstall() {
  if (!guide.value) return;
  await navigator.clipboard.writeText(guide.value.install_command);
  message.success('一键安装命令已复制');
}

async function copyNginx() {
  if (!guide.value) return;
  await navigator.clipboard.writeText(guide.value.nginx_config);
  message.success('Nginx 配置已复制');
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">接入指引</h2>
      <p class="text-sm text-[rgb(125,125,125)]">一键安装 WAF 组件到 /opt/waf 并接入本机 OpenResty</p>
    </div>

    <NAlert v-if="!guide && !loading" type="warning" title="无法获取接入指引">
      请先完成 Redis 配置（引导页/系统配置），以便生成一键安装命令。
    </NAlert>

    <!-- 一键安装 -->
    <NCard v-if="guide" :bordered="false" class="card-wrapper" title="一键安装 WAF 组件（安装到 /opt/waf）">
      <template #header-extra>
        <NSpace>
          <NButton size="small" type="primary" @click="copyInstall">复制安装命令</NButton>
          <NButton size="small" secondary tag="a" :href="guide.download_url" download="waf.tar.gz">
            下载 waf.tar.gz
          </NButton>
        </NSpace>
      </template>
      <NCode :code="guide.install_command" language="bash" word-wrap />
      <div class="mt-3 flex flex-wrap gap-4 text-sm">
        <div class="flex items-center gap-2">
          <NTag size="small" type="info" bordered>Redis</NTag>
          <span class="font-mono text-xs">{{ guide.redis.addr }} / db{{ guide.redis.db }}</span>
        </div>
        <div class="text-xs text-[rgb(125,125,125)]">
          脚本会将 Lua 组件解压到 /opt/waf（init.lua 位于 /opt/waf/init.lua），并写入 config_local.lua（Redis 连接）
        </div>
      </div>
    </NCard>

    <!-- Nginx 接入 -->
    <NCard v-if="guide" :bordered="false" class="card-wrapper" title="Nginx 接入配置">
      <template #header-extra>
        <NButton size="small" type="primary" @click="copyNginx">复制配置</NButton>
      </template>
      <NCode :code="guide.nginx_config" language="nginx" word-wrap />
    </NCard>

    <!-- 部署说明 -->
    <NCard :bordered="false" class="card-wrapper" title="部署说明">
      <div class="space-y-2 text-sm">
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>1</NTag>
          <span>复制上方一键安装命令在 OpenResty 服务器执行，组件安装至 <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-xs">/opt/waf</code></span>
        </div>
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>2</NTag>
          <span>将 Nginx 接入配置加入需要防护的 server/location，reload 生效</span>
        </div>
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>3</NTag>
          <span>IP 归属地：将 <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-xs">ip2region_v4.xdb</code> 放入 /opt/waf（可选，缺失自动降级）</span>
        </div>
        <div class="flex items-center gap-2">
          <NTag type="primary" size="small" bordered>4</NTag>
          <span>「规则管理」修改规则后点击「发布到引擎」，5 秒内热更新生效</span>
        </div>
      </div>
    </NCard>
  </div>
</template>
