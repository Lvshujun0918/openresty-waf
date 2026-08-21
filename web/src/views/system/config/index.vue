<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NInputNumber, NRadio, NRadioGroup, NSpace, NSwitch, NTag } from 'naive-ui';
import { fetchConfig, fetchConfigVersions, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const versions = ref({ engine_version: '', rule_version: '', config_version: '' });
const cfg = reactive({
  mode: 'active',
  detection: { exclude_paths: [] as string[], geo: true, paranoia_level: 1, watchdog_ms: 10, response_body_buffer: 8192 },
  upload: { enabled: true, spooled_scan_bytes: 524288 },
  cc: { rate_count: 100, rate_seconds: 60, ban_duration: 300 },
  auto_ban: { enabled: true, threshold: 10, window: 60, duration: 600 }
});
const excludeText = ref('');
const staticExtText = ref('');
const staticPrefixText = ref('');
const trustedText = ref('');
const ipHeaderText = ref('');
const uploadExtText = ref('');
const uploadMimeText = ref('');
// 证据脱敏 / 响应安全头
const maskEnabled = ref(true);
const maskFieldsText = ref('');
const maskRegexText = ref('');
const rhAddText = ref('');
const rhRemoveText = ref('');
let rawConfig: Record<string, unknown> = {};

function asList(v: unknown): string[] {
  return Array.isArray(v) ? (v as string[]) : [];
}

function parseRate(rate: unknown): { count: number; seconds: number } {
  const m = String(rate || '100/60').match(/^(\d+)\/(\d+)$/);
  return { count: m ? Number(m[1]) : 100, seconds: m ? Number(m[2]) : 60 };
}

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
  const cc = (rawConfig.cc as Record<string, unknown>) ?? {};
  const ab = (rawConfig.auto_ban as Record<string, unknown>) ?? {};
  const rate = parseRate(cc.rate);
  Object.assign(cfg, {
    mode: rawConfig.mode || 'active',
    detection: {
      exclude_paths: asList(det.exclude_paths),
      geo: det.geo !== false,
      paranoia_level: Number(det.paranoia_level) || 1,
      watchdog_ms: Number(det.watchdog_ms) || 0,
      response_body_buffer: Number(det.response_body_buffer) || 8192
    },
    upload: {
      enabled: ((rawConfig.upload as Record<string, unknown>) ?? {}).enabled !== false,
      spooled_scan_bytes: Number(((rawConfig.upload as Record<string, unknown>) ?? {}).spooled_scan_bytes) || 524288
    },
    cc: {
      rate_count: rate.count,
      rate_seconds: rate.seconds,
      ban_duration: Number(cc.ban_duration) || 300
    },
    auto_ban: {
      enabled: ab.enabled !== false,
      threshold: Number(ab.threshold) || 10,
      window: Number(ab.window) || 60,
      duration: Number(ab.duration) || 600
    }
  });
  excludeText.value = cfg.detection.exclude_paths.join('\n');
  staticExtText.value = asList(skip.ext).join('\n');
  staticPrefixText.value = asList(skip.prefix).join('\n');
  trustedText.value = asList(rawConfig.trusted_proxies).join('\n');
  ipHeaderText.value = String(rawConfig.client_ip_header || '');
  // 证据脱敏
  const mask = (det.evidence_mask as Record<string, unknown>) ?? {};
  maskEnabled.value = mask.enabled !== false;
  maskFieldsText.value = asList(mask.fields).join('\n');
  maskRegexText.value = asList(mask.regex).join('\n');
  // 响应安全头
  const rh = (det.response_headers as Record<string, unknown>) ?? {};
  rhAddText.value = Object.entries((rh.add as Record<string, unknown>) ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  rhRemoveText.value = asList(rh.remove).join('\n');
  const up = (rawConfig.upload as Record<string, unknown>) ?? {};
  uploadExtText.value = asList(up.deny_ext).join('\n');
  uploadMimeText.value = asList(up.deny_mime).join('\n');
  loaded.value = true;
}

async function loadVersions() {
  const res = await fetchConfigVersions();
  if (res.data) versions.value = res.data;
}

async function save() {
  saving.value = true;
  try {
    const lines = (s: string) =>
      s
        .split('\n')
        .map(v => v.trim())
        .filter(Boolean);
    const excludePaths = lines(excludeText.value);
    const staticExt = lines(staticExtText.value);
    const staticPrefix = lines(staticPrefixText.value);
    const trusted = lines(trustedText.value);
    const uploadExt = lines(uploadExtText.value);
    const uploadMime = lines(uploadMimeText.value);
    const rawDet = (rawConfig.detection as Record<string, unknown>) ?? {};
    const rawUp = (rawConfig.upload as Record<string, unknown>) ?? {};
    const rawCc = (rawConfig.cc as Record<string, unknown>) ?? {};
    const rawAb = (rawConfig.auto_ban as Record<string, unknown>) ?? {};
    const next = {
      ...rawConfig,
      mode: cfg.mode,
      detection: {
        ...rawDet,
        exclude_paths: excludePaths,
        geo: cfg.detection.geo,
        paranoia_level: cfg.detection.paranoia_level,
        watchdog_ms: cfg.detection.watchdog_ms,
        response_body_buffer: cfg.detection.response_body_buffer,
        skip_static: {
          ...((rawDet.skip_static as Record<string, unknown>) ?? {}),
          ext: staticExt,
          prefix: staticPrefix
        },
        evidence_mask: {
          enabled: maskEnabled.value,
          fields: lines(maskFieldsText.value),
          regex: lines(maskRegexText.value)
        },
        response_headers: {
          add: Object.fromEntries(
            lines(rhAddText.value)
              .map(l => {
                const idx = l.indexOf(':');
                return idx > 0 ? [l.slice(0, idx).trim(), l.slice(idx + 1).trim()] : null;
              })
              .filter((x): x is [string, string] => !!x)
          ),
          remove: lines(rhRemoveText.value)
        }
      },
      upload: {
        ...rawUp,
        enabled: cfg.upload.enabled,
        spooled_scan_bytes: cfg.upload.spooled_scan_bytes,
        deny_ext: uploadExt,
        deny_mime: uploadMime
      },
      cc: {
        ...rawCc,
        rate: `${cfg.cc.rate_count}/${cfg.cc.rate_seconds}`,
        ban_duration: cfg.cc.ban_duration
      },
      auto_ban: {
        ...rawAb,
        enabled: cfg.auto_ban.enabled,
        threshold: cfg.auto_ban.threshold,
        window: cfg.auto_ban.window,
        duration: cfg.auto_ban.duration
      },
      trusted_proxies: trusted,
      client_ip_header: ipHeaderText.value.trim()
    };
    await saveConfig(next);
    window.$message?.success('配置已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    saving.value = false;
  }
}

onMounted(load);
onMounted(loadVersions);
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">系统配置</h2>
      <p class="text-sm text-[rgb(125,125,125)]">防护模式、检测策略与日志后端配置</p>
    </div>

    <NCard :bordered="false" class="card-wrapper" title="版本健康">
      <NSpace size="large">
        <div>
          <p class="text-xs text-[rgb(125,125,125)]">引擎版本（最近事件上报）</p>
          <p class="mt-1 font-mono text-sm">{{ versions.engine_version || '尚未上报' }}</p>
        </div>
        <div>
          <p class="text-xs text-[rgb(125,125,125)]">规则下发版本（Redis）</p>
          <p class="mt-1 font-mono text-sm">{{ versions.rule_version ? '#' + versions.rule_version : '未下发' }}</p>
        </div>
        <div>
          <p class="text-xs text-[rgb(125,125,125)]">配置下发版本（Redis）</p>
          <p class="mt-1 font-mono text-sm">{{ versions.config_version ? '#' + versions.config_version : '未下发' }}</p>
        </div>
        <NButton size="small" quaternary type="primary" @click="loadVersions">刷新</NButton>
      </NSpace>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="防护模式">
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

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="检测策略">
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
        <NFormItem label="检测 watchdog（毫秒）">
          <NInputNumber v-model:value="cfg.detection.watchdog_ms" :min="0" :max="1000" :step="1" class="w-40" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">检测总耗时超阈值强制放行（0 关闭），灾难性回溯的最后防线</span>
        </NFormItem>
        <NFormItem label="响应体检测缓冲（字节）">
          <NInputNumber v-model:value="cfg.detection.response_body_buffer" :min="1024" :max="1048576" :step="1024" class="w-40" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">响应体 DLP 检测的缓冲上限，默认 8192</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="可信代理（X-Forwarded-For）">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="可信代理列表">
          <div class="w-full">
            <NInput v-model:value="trustedText" type="textarea" :rows="3" placeholder="每行一个精确 IP 或 CIDR，如 10.0.0.0/8&#10;留空 = 无条件信任 XFF（兼容旧行为）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">仅当直连地址命中此列表时才信任 XFF 最左值；公网直连部署建议配置，防止伪造 XFF 绕过 IP 名单/CC/人机验证</p>
          </div>
        </NFormItem>
        <NFormItem label="来源 IP 自定义头">
          <div class="w-full">
            <NInput v-model:value="ipHeaderText" placeholder="如 eo-connecting-ip（腾讯云 EdgeOne）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">CDN 把真实客户端 IP 放在私有头且回源 IP 不公开时填写；优先级高于 XFF，仅接受合法 IP 值</p>
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="文件上传检测">
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
        <NFormItem label="落盘扫描字节数">
          <NInputNumber v-model:value="cfg.upload.spooled_scan_bytes" :min="65536" :max="10485760" :step="65536" class="w-48" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">超大上传落临时文件时流式扫描文件前缀字节数，默认 512KB</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="高频攻击自动封禁">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="自动封禁">
          <NSwitch v-model:value="cfg.auto_ban.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">同 IP 短窗口内多次攻击命中后自动临时封禁（白名单不受影响）</span>
        </NFormItem>
        <NFormItem label="触发条件">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">窗口</span>
            <NInputNumber v-model:value="cfg.auto_ban.window" :min="10" :max="3600" class="w-28" />
            <span class="text-sm text-[rgb(125,125,125)]">秒内攻击</span>
            <NInputNumber v-model:value="cfg.auto_ban.threshold" :min="2" :max="1000" class="w-28" />
            <span class="text-sm text-[rgb(125,125,125)]">次</span>
          </NSpace>
        </NFormItem>
        <NFormItem label="封禁时长(s)">
          <NInputNumber v-model:value="cfg.auto_ban.duration" :min="60" :max="86400" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">默认 10 次/60 秒触发，封禁 10 分钟</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="证据脱敏（隐私合规）">
      <NForm label-placement="left" label-width="120">
        <NFormItem label="启用">
          <NSwitch v-model:value="maskEnabled" />
        </NFormItem>
        <NFormItem label="敏感字段">
          <NInput
            v-model:value="maskFieldsText"
            type="textarea"
            :rows="3"
            placeholder="每行一个字段名，如 password / token / secret（命中键名即打码）"
          />
        </NFormItem>
        <NFormItem label="正则打码">
          <NInput
            v-model:value="maskRegexText"
            type="textarea"
            :rows="3"
            placeholder="每行一个正则，如 1[3-9]\d{9}（手机号）"
          />
        </NFormItem>
        <NFormItem label="说明">
          <span class="text-xs text-[rgb(125,125,125)]">攻击事件入库前对请求头/请求体中的敏感值打码为 ***</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="响应安全头加固">
      <NForm label-placement="left" label-width="120">
        <NFormItem label="添加/覆盖">
          <NInput
            v-model:value="rhAddText"
            type="textarea"
            :rows="4"
            placeholder="每行一个「头: 值」，如&#10;Strict-Transport-Security: max-age=31536000&#10;Content-Security-Policy: default-src 'self'"
          />
        </NFormItem>
        <NFormItem label="移除">
          <NInput
            v-model:value="rhRemoveText"
            type="textarea"
            :rows="2"
            placeholder="每行一个头名，如 Server / X-Powered-By"
          />
        </NFormItem>
        <NFormItem label="说明">
          <span class="text-xs text-[rgb(125,125,125)]">需挂载 header_filter.lua；默认已加 X-Content-Type-Options 等基础头</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard v-if="loaded" :bordered="false" class="card-wrapper" title="CC 防刷（全局缺省）">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="频率阈值">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">每</span>
            <NInputNumber v-model:value="cfg.cc.rate_seconds" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">秒内最多</span>
            <NInputNumber v-model:value="cfg.cc.rate_count" :min="1" class="w-28" />
            <span class="text-sm text-[rgb(125,125,125)]">次</span>
          </NSpace>
        </NFormItem>
        <NFormItem label="封禁时长(s)">
          <NInputNumber v-model:value="cfg.cc.ban_duration" :min="1" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">超限后封禁该 IP 的秒数</span>
        </NFormItem>
        <p class="text-xs text-[rgb(125,125,125)]">全局缺省值；在「触发规则」页创建 CC 规则可对特定域名/路径单独配置阈值与维度</p>
      </NForm>
    </NCard>

    <div v-if="loaded">
      <NButton type="primary" :loading="saving" @click="save">保存全部配置</NButton>
    </div>
  </div>
</template>
