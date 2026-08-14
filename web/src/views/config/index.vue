<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NRadio, NRadioGroup, NSpace, NSwitch, NTag } from 'naive-ui';
import { fetchConfig, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const cfg = reactive({
  mode: 'active',
  detection: { exclude_paths: [] as string[], geo: true, paranoia_level: 1 },
  log: { enabled: true, backend: 'redis' },
  upload: { enabled: true }
});
const excludeText = ref('');
const staticExtText = ref('');
const staticPrefixText = ref('');
const trustedText = ref('');
const uploadExtText = ref('');
const uploadMimeText = ref('');
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
  const skip = (det.skip_static as Record<string, unknown>) ?? {};
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
    },
    upload: {
      enabled: ((rawConfig.upload as Record<string, unknown>) ?? {}).enabled !== false
    }
  });
  excludeText.value = cfg.detection.exclude_paths.join('\n');
  staticExtText.value = (Array.isArray(skip.ext) ? (skip.ext as string[]) : []).join('\n');
  staticPrefixText.value = (Array.isArray(skip.prefix) ? (skip.prefix as string[]) : []).join('\n');
  trustedText.value = (Array.isArray(rawConfig.trusted_proxies) ? (rawConfig.trusted_proxies as string[]) : []).join('\n');
  const up = (rawConfig.upload as Record<string, unknown>) ?? {};
  uploadExtText.value = (Array.isArray(up.deny_ext) ? (up.deny_ext as string[]) : []).join('\n');
  uploadMimeText.value = (Array.isArray(up.deny_mime) ? (up.deny_mime as string[]) : []).join('\n');
  loaded.value = true;
}

async function save() {
  saving.value = true;
  try {
    const excludePaths = excludeText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const staticExt = staticExtText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const staticPrefix = staticPrefixText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const trusted = trustedText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const uploadExt = uploadExtText.value
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);
    const uploadMime = uploadMimeText.value
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
        paranoia_level: cfg.detection.paranoia_level,
        skip_static: {
          ...(((rawConfig.detection as Record<string, unknown>)?.skip_static as Record<string, unknown>) ?? {}),
          ext: staticExt,
          prefix: staticPrefix
        }
      },
      log: {
        ...((rawConfig.log as Record<string, unknown>) ?? {}),
        enabled: cfg.log.enabled,
        backend: cfg.log.backend
      },
      upload: {
        ...((rawConfig.upload as Record<string, unknown>) ?? {}),
        enabled: cfg.upload.enabled,
        deny_ext: uploadExt,
        deny_mime: uploadMime
      },
      trusted_proxies: trusted
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
        <NFormItem label="静态剪枝·后缀">
          <div class="w-full">
            <NInput v-model:value="staticExtText" type="textarea" :rows="3" placeholder="每行一个后缀，如 .js、.css（命中后跳过规则检测，性能优化）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">默认已包含常见图片/字体/JS/CSS 后缀；IP 名单、CC、人机验证仍生效</p>
          </div>
        </NFormItem>
        <NFormItem label="静态剪枝·前缀">
          <div class="w-full">
            <NInput v-model:value="staticPrefixText" type="textarea" :rows="2" placeholder="每行一个路径前缀，如 /static/、/assets/" />
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="可信代理（X-Forwarded-For）">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="可信代理列表">
          <div class="w-full">
            <NInput v-model:value="trustedText" type="textarea" :rows="3" placeholder="每行一个精确 IP 或 CIDR，如 10.0.0.0/8&#10;留空 = 无条件信任 XFF（兼容旧行为）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">仅当直连地址命中此列表时才信任 XFF 最左值；公网直连部署建议配置，防止伪造 XFF 绕过 IP 名单/CC/人机验证</p>
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="文件上传检测">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="上传检测">
          <NSwitch v-model:value="cfg.upload.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">检测 multipart 上传的文件名后缀与 Content-Type</span>
        </NFormItem>
        <NFormItem label="危险后缀">
          <div class="w-full">
            <NInput v-model:value="uploadExtText" type="textarea" :rows="3" placeholder="每行一个后缀（不含点），如 php、jsp、exe" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">文件名以此后缀结尾即拦截（不区分大小写）</p>
          </div>
        </NFormItem>
        <NFormItem label="危险类型">
          <div class="w-full">
            <NInput v-model:value="uploadMimeText" type="textarea" :rows="2" placeholder="每行一个 Content-Type，如 application/x-php" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">伪造后缀但类型命中黑名单同样拦截</p>
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
