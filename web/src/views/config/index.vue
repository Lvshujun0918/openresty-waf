<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NRadio, NRadioGroup, NSpace, NSwitch, NTag } from 'naive-ui';
import { fetchConfig, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const cfg = reactive({
  mode: 'active',
  detection: { exclude_paths: [] as string[], geo: true, paranoia_level: 1 },
  log: { enabled: true, backend: 'redis' }
});
const excludeText = ref('');
let rawConfig: Record<string, unknown> = {};

const modeOptions = [
  { label: '拦截模式', value: 'active', desc: '命中规则即阻断，全量防护已开启' },
  { label: '监控模式', value: 'detect', desc: '仅记录攻击日志，不阻断请求' },
  { label: '放行模式', value: 'off', desc: '旁路运行，不执行检测' }
];
const currentMode = computed(() => modeOptions.find(m => m.value === cfg.mode));

async function load() {
  const res = await fetchConfig();
  rawConfig = res.data?.config ?? {};
  const det = (rawConfig.detection as Record<string, unknown>) ?? {};
  const log = (rawConfig.log as Record<string, unknown>) ?? {};
  Object.assign(cfg, {
    mode: rawConfig.mode || 'active',
    detection: {
      exclude_paths: Array.isArray(det.exclude_paths) ? (det.exclude_paths as string[]) : [],
      geo: det.geo !== false,
      paranoia_level: Number(det.paranoia_level) || 1
    },
    log: {
      enabled: log.enabled !== false,
      backend: log.backend || 'redis'
    }
  });
  excludeText.value = cfg.detection.exclude_paths.join('\n');
  loaded.value = true;
}

async function save() {
  saving.value = true;
  try {
    const excludePaths = excludeText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const next = {
      ...rawConfig,
      mode: cfg.mode,
      detection: {
        ...((rawConfig.detection as Record<string, unknown>) ?? {}),
        exclude_paths: excludePaths,
        geo: cfg.detection.geo,
        paranoia_level: cfg.detection.paranoia_level
      },
      log: {
        ...((rawConfig.log as Record<string, unknown>) ?? {}),
        enabled: cfg.log.enabled,
        backend: cfg.log.backend
      }
    };
    await saveConfig(next);
    window.$message?.success('配置已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">系统配置</h2>
      <p class="text-sm text-[rgb(125,125,125)]">防护模式、检测策略与日志后端配置</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="防护模式">
      <NRadioGroup v-model:value="cfg.mode">
        <NSpace>
          <NCard v-for="m in modeOptions" :key="m.value" size="small" :class="cfg.mode === m.value ? 'ring-2 ring-[#2563eb]' : ''" style="width: 220px">
            <template #header>
              <NRadio :value="m.value" :label="m.label" />
            </template>
            <p class="text-xs text-[rgb(125,125,125)]">{{ m.desc }}</p>
          </NCard>
        </NSpace>
      </NRadioGroup>
      <p v-if="currentMode" class="mt-2 text-xs text-[rgb(125,125,125)]">当前：{{ currentMode.label }}</p>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="检测策略">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="CRS 偏执级别">
          <NSpace>
            <NTag :type="cfg.detection.paranoia_level === 1 ? 'primary' : 'default'" bordered>PL1（标准，推荐）</NTag>
            <NTag :type="cfg.detection.paranoia_level === 2 ? 'primary' : 'default'" bordered>PL2（增强，误报更高）</NTag>
          </NSpace>
          <NButton size="small" quaternary type="primary" @click="cfg.detection.paranoia_level = cfg.detection.paranoia_level === 1 ? 2 : 1">
            切换为 PL{{ cfg.detection.paranoia_level === 1 ? 2 : 1 }}
          </NButton>
        </NFormItem>
        <NFormItem label="IP 归属地解析">
          <NSwitch v-model:value="cfg.detection.geo" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">需 /opt/waf/ip2region_v4.xdb 数据文件</span>
        </NFormItem>
        <NFormItem label="豁免路径">
          <div class="w-full">
            <NInput v-model:value="excludeText" type="textarea" :rows="4" placeholder="每行一个前缀路径，如 /api、/health（命中前缀跳过规则检测，IP/CC 仍生效）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">用于规避 JSON API 误报</p>
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="日志">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="攻击日志">
          <NSwitch v-model:value="cfg.log.enabled" />
        </NFormItem>
        <NFormItem label="后端">
          <NRadioGroup v-model:value="cfg.log.backend">
            <NSpace>
              <NRadio value="redis" label="Redis（后台消费展示，推荐）" />
              <NRadio value="file" label="本地文件（/var/log/waf）" />
            </NSpace>
          </NRadioGroup>
        </NFormItem>
      </NForm>
    </NCard>

    <div v-if="loaded">
      <NButton type="primary" :loading="saving" @click="save">保存全部配置</NButton>
    </div>
  </div>
</template>
