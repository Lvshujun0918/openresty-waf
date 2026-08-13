<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { NAlert, NButton, NCard, NCode, NForm, NFormItem, NInput, NInputNumber, NModal, NSpace, NTag, useMessage } from 'naive-ui';
import { fetchSetupGuide, saveRedisConfig } from '@/service/api';

interface SetupGuide {
  redis: { addr: string; password: string; db: number };
  install_command: string;
  install_command_force: string;
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
    if (guide.value) {
      Object.assign(redisForm, {
        addr: guide.value.redis.addr || '',
        password: guide.value.redis.password || '',
        db: guide.value.redis.db || 0
      });
    }
  } finally {
    loading.value = false;
  }
}

// —— Redis 配置 ——
const editOpen = ref(false);
const saving = ref(false);
const redisForm = reactive({ addr: '', password: '', db: 0 });

function openRedisEdit() {
  if (!guide.value) return;
  Object.assign(redisForm, {
    addr: guide.value.redis.addr,
    password: guide.value.redis.password,
    db: guide.value.redis.db
  });
  editOpen.value = true;
}

async function saveRedis() {
  if (!redisForm.addr.trim()) {
    message.warning('请填写 Redis 地址');
    return;
  }
  saving.value = true;
  try {
    await saveRedisConfig({ addr: redisForm.addr.trim(), password: redisForm.password, db: redisForm.db });
    message.success('Redis 配置已保存');
    editOpen.value = false;
    await load();
  } catch (e) {
    message.error('保存失败，请检查 Redis 连接');
  } finally {
    saving.value = false;
  }
}

async function copyInstall() {
  if (!guide.value) return;
  await navigator.clipboard.writeText(guide.value.install_command);
  message.success('安装命令已复制（更新组件，保留现有 Redis 配置）');
}

async function copyInstallForce() {
  if (!guide.value) return;
  await navigator.clipboard.writeText(guide.value.install_command_force);
  message.success('强制覆盖命令已复制（更新组件并同步 Redis 配置）');
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
      请先配置 Redis 连接（下方「Redis 配置」），以便生成一键安装命令。
    </NAlert>

    <!-- Redis 配置 -->
    <NCard :bordered="false" class="card-wrapper" title="Redis 配置">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2 text-sm">
          <NTag type="info" size="small" bordered>Redis</NTag>
          <template v-if="guide">
            <span class="font-mono text-xs">{{ guide.redis.addr }}</span>
            <span class="text-xs text-[rgb(125,125,125)]">db{{ guide.redis.db }}</span>
          </template>
          <span v-else class="text-xs text-[rgb(125,125,125)]">未配置</span>
        </div>
        <NButton size="small" type="primary" secondary @click="openRedisEdit">修改 Redis 配置</NButton>
      </div>
      <p class="mt-2 text-xs text-[rgb(125,125,125)]">
        引擎通过 Redis 接收规则/配置热更新、上报攻击事件。修改后请重新复制「强制覆盖」安装命令同步到下游引擎。
      </p>
    </NCard>

    <!-- 一键安装 -->
    <NCard v-if="guide" :bordered="false" class="card-wrapper" title="一键安装 WAF 组件（安装到 /opt/waf）">
      <div class="mb-2 text-sm font-medium text-[rgb(60,60,60)]">普通安装 / 更新组件</div>
      <div class="flex items-start gap-2">
        <NCode :code="guide.install_command" language="bash" word-wrap class="flex-1" />
        <NButton size="small" type="primary" @click="copyInstall">复制</NButton>
      </div>
      <p class="mt-1 text-xs text-[rgb(125,125,125)]">更新组件文件；已存在 config_local.lua 时保留现有 Redis 配置</p>

      <div class="mt-4 mb-2 text-sm font-medium text-[rgb(60,60,60)]">强制覆盖 Redis 配置（修改 Redis 后快速同步下游引擎）</div>
      <div class="flex items-start gap-2">
        <NCode :code="guide.install_command_force" language="bash" word-wrap class="flex-1" />
        <NButton size="small" type="warning" secondary @click="copyInstallForce">复制</NButton>
      </div>
      <p class="mt-1 text-xs text-[rgb(125,125,125)]">
        追加 <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-[11px]">-f</code> 参数：重新生成
        <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-[11px]">config_local.lua</code>
        （按当前 Redis 配置覆盖），随后 <code class="rounded bg-[rgb(245,245,245)] px-1 font-mono text-[11px]">nginx -s reload</code> 生效
      </p>
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

    <!-- Redis 配置弹窗 -->
    <NModal v-model:show="editOpen" preset="card" title="修改 Redis 配置" class="w-[min(96vw,480px)]" :style="{ borderRadius: '12px' }">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="地址" required>
          <NInput v-model:value="redisForm.addr" placeholder="如 127.0.0.1:6379 或 redis:6379" />
        </NFormItem>
        <NFormItem label="密码">
          <NInput v-model:value="redisForm.password" type="password" show-password-on="click" placeholder="无密码留空" />
        </NFormItem>
        <NFormItem label="库号">
          <NInputNumber v-model:value="redisForm.db" :min="0" :max="15" class="w-32" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editOpen = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="saveRedis">测试并保存</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
