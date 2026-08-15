<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NInputNumber, NRadio, NRadioGroup, NSelect, NSpace, NSwitch, NTag } from 'naive-ui';
import { fetchConfig, fetchConfigVersions, saveConfig } from '@/service/api';

const saving = ref(false);
const loaded = ref(false);
const versions = ref({ engine_version: '', rule_version: '', config_version: '' });
const cfg = reactive({
  mode: 'active',
  detection: { exclude_paths: [] as string[], geo: true, paranoia_level: 1, watchdog_ms: 10, response_body_buffer: 8192 },
  log: { enabled: true, backend: 'redis', dir: '/var/log/waf', format: 'json', level: 'info', redis_key: 'waf:event:list' },
  upload: { enabled: true, spooled_scan_bytes: 524288 },
  block: { status: 403 },
  cc: { rate_count: 100, rate_seconds: 60, ban_duration: 300 },
  challenge: {
    enabled: true,
    mode: 'basic',
    pow_bits: 20,
    cookie_ttl: 300,
    issue_limit: 20,
    issue_window: 60,
    cookie_secret: '',
    captcha_id: '',
    captcha_key: ''
  },
  traffic_log: { enabled: false, retention_days: 7 },
  auto_ban: { enabled: true, threshold: 10, window: 60, duration: 600 }
});
const excludeText = ref('');
const staticExtText = ref('');
const staticPrefixText = ref('');
const trustedText = ref('');
const uploadExtText = ref('');
const uploadMimeText = ref('');
const blockHtmlText = ref('');
const wlIpText = ref('');
const wlUrlText = ref('');
const wlUaText = ref('');
const blIpText = ref('');
const blUrlText = ref('');
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
  const block = (rawConfig.block as Record<string, unknown>) ?? {};
  const ch = (rawConfig.challenge as Record<string, unknown>) ?? {};
  const captcha = (ch.captcha as Record<string, unknown>) ?? {};
  const tl = (rawConfig.traffic_log as Record<string, unknown>) ?? {};
  const ab = (rawConfig.auto_ban as Record<string, unknown>) ?? {};
  const wl = (rawConfig.whitelist as Record<string, unknown>) ?? {};
  const bl = (rawConfig.blacklist as Record<string, unknown>) ?? {};
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
    log: {
      enabled: log.enabled !== false,
      backend: log.backend || 'redis',
      dir: String(log.dir || '/var/log/waf'),
      format: String(log.format || 'json'),
      level: String(log.level || 'info'),
      redis_key: String(log.redis_key || 'waf:event:list')
    },
    upload: {
      enabled: ((rawConfig.upload as Record<string, unknown>) ?? {}).enabled !== false,
      spooled_scan_bytes: Number(((rawConfig.upload as Record<string, unknown>) ?? {}).spooled_scan_bytes) || 524288
    },
    block: {
      status: Number(block.status) || 403
    },
    cc: {
      rate_count: rate.count,
      rate_seconds: rate.seconds,
      ban_duration: Number(cc.ban_duration) || 300
    },
    challenge: {
      enabled: ch.enabled !== false,
      mode: String(ch.mode || 'basic'),
      pow_bits: Number(ch.pow_bits) || 0,
      cookie_ttl: Number(ch.cookie_ttl) || 300,
      issue_limit: Number(ch.issue_limit) || 0,
      issue_window: Number(ch.issue_window) || 60,
      cookie_secret: String(ch.cookie_secret || ''),
      captcha_id: String(captcha.id || ''),
      captcha_key: String(captcha.key || '')
    },
    traffic_log: {
      enabled: tl.enabled === true,
      retention_days: Number(tl.retention_days) || 7
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
  const up = (rawConfig.upload as Record<string, unknown>) ?? {};
  uploadExtText.value = asList(up.deny_ext).join('\n');
  uploadMimeText.value = asList(up.deny_mime).join('\n');
  blockHtmlText.value = String(block.html || '');
  wlIpText.value = asList(wl.ips).join('\n');
  wlUrlText.value = asList(wl.urls).join('\n');
  wlUaText.value = asList(wl.user_agents).join('\n');
  blIpText.value = asList(bl.ips).join('\n');
  blUrlText.value = asList(bl.urls).join('\n');
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
    const wlIps = lines(wlIpText.value);
    const wlUrls = lines(wlUrlText.value);
    const wlUas = lines(wlUaText.value);
    const blIps = lines(blIpText.value);
    const blUrls = lines(blUrlText.value);
    const rawDet = (rawConfig.detection as Record<string, unknown>) ?? {};
    const rawLog = (rawConfig.log as Record<string, unknown>) ?? {};
    const rawUp = (rawConfig.upload as Record<string, unknown>) ?? {};
    const rawBlock = (rawConfig.block as Record<string, unknown>) ?? {};
    const rawCc = (rawConfig.cc as Record<string, unknown>) ?? {};
    const rawCh = (rawConfig.challenge as Record<string, unknown>) ?? {};
    const rawCaptcha = (rawCh.captcha as Record<string, unknown>) ?? {};
    const rawTl = (rawConfig.traffic_log as Record<string, unknown>) ?? {};
    const rawAb = (rawConfig.auto_ban as Record<string, unknown>) ?? {};
    const rawWl = (rawConfig.whitelist as Record<string, unknown>) ?? {};
    const rawBl = (rawConfig.blacklist as Record<string, unknown>) ?? {};
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
        }
      },
      log: {
        ...rawLog,
        enabled: cfg.log.enabled,
        backend: cfg.log.backend,
        dir: cfg.log.dir,
        format: cfg.log.format,
        level: cfg.log.level,
        redis_key: cfg.log.redis_key
      },
      upload: {
        ...rawUp,
        enabled: cfg.upload.enabled,
        spooled_scan_bytes: cfg.upload.spooled_scan_bytes,
        deny_ext: uploadExt,
        deny_mime: uploadMime
      },
      block: {
        ...rawBlock,
        status: cfg.block.status,
        html: blockHtmlText.value
      },
      cc: {
        ...rawCc,
        rate: `${cfg.cc.rate_count}/${cfg.cc.rate_seconds}`,
        ban_duration: cfg.cc.ban_duration
      },
      challenge: {
        ...rawCh,
        enabled: cfg.challenge.enabled,
        mode: cfg.challenge.mode,
        pow_bits: cfg.challenge.pow_bits,
        cookie_ttl: cfg.challenge.cookie_ttl,
        issue_limit: cfg.challenge.issue_limit,
        issue_window: cfg.challenge.issue_window,
        cookie_secret: cfg.challenge.cookie_secret,
        captcha: {
          ...rawCaptcha,
          id: cfg.challenge.captcha_id,
          key: cfg.challenge.captcha_key
        }
      },
      traffic_log: {
        ...rawTl,
        enabled: cfg.traffic_log.enabled,
        retention_days: cfg.traffic_log.retention_days
      },
      auto_ban: {
        ...rawAb,
        enabled: cfg.auto_ban.enabled,
        threshold: cfg.auto_ban.threshold,
        window: cfg.auto_ban.window,
        duration: cfg.auto_ban.duration
      },
      whitelist: {
        ...rawWl,
        ips: wlIps,
        urls: wlUrls,
        user_agents: wlUas
      },
      blacklist: {
        ...rawBl,
        ips: blIps,
        urls: blUrls
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
        <NFormItem label="落盘扫描字节数">
          <NInputNumber v-model:value="cfg.upload.spooled_scan_bytes" :min="65536" :max="10485760" :step="65536" class="w-48" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">超大上传落临时文件时流式扫描文件前缀字节数，默认 512KB</span>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="高频攻击自动封禁">
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

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="拦截响应">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="状态码">
          <NInputNumber v-model:value="cfg.block.status" :min="400" :max="599" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">命中拦截时返回的 HTTP 状态码（默认 403）</span>
        </NFormItem>
        <NFormItem label="拦截页面 HTML">
          <div class="w-full">
            <NInput v-model:value="blockHtmlText" type="textarea" :rows="6" placeholder="自定义拦截页面 HTML，留空使用引擎内置页面" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">留空时使用内置拦截页</p>
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="CC 防刷（全局缺省）">
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

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="人机验证">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="启用">
          <NSwitch v-model:value="cfg.challenge.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">CC 超限后进入验证页（触发规则命中时不受此开关限制）</span>
        </NFormItem>
        <NFormItem label="验证模式">
          <NRadioGroup v-model:value="cfg.challenge.mode">
            <NSpace>
              <NRadio value="basic" label="basic（JS 工作量证明）" />
              <NRadio value="geetest" label="geetest（极验）" />
              <NRadio value="gitee" label="gitee（Gitee 验证码）" />
            </NSpace>
          </NRadioGroup>
        </NFormItem>
        <template v-if="cfg.challenge.mode !== 'basic'">
          <NFormItem label="Captcha ID">
            <NInput v-model:value="cfg.challenge.captcha_id" class="w-80" placeholder="验证码服务商分配的 captcha_id" />
          </NFormItem>
          <NFormItem label="Captcha Key">
            <NInput v-model:value="cfg.challenge.captcha_key" class="w-80" type="password" show-password-on="click" placeholder="验证码服务商分配的 captcha_key" />
          </NFormItem>
        </template>
        <NFormItem label="POW 难度(bit)">
          <NInputNumber v-model:value="cfg.challenge.pow_bits" :min="0" :max="28" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">basic 模式哈希前导零位数（0 关闭，默认 20）</span>
        </NFormItem>
        <NFormItem label="放行时长(s)">
          <NInputNumber v-model:value="cfg.challenge.cookie_ttl" :min="60" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">验证通过后 Cookie 放行时长</span>
        </NFormItem>
        <NFormItem label="签发限频">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">每</span>
            <NInputNumber v-model:value="cfg.challenge.issue_window" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">秒最多下发</span>
            <NInputNumber v-model:value="cfg.challenge.issue_limit" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">次（超限 444）</span>
          </NSpace>
        </NFormItem>
        <NFormItem label="签名密钥">
          <div class="w-full">
            <NInput v-model:value="cfg.challenge.cookie_secret" class="w-96" type="password" show-password-on="click" placeholder="cookie_secret（生产环境务必修改）" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">用于签名验证 Cookie 与挑战 token，修改后已签发的验证立即失效</p>
          </div>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="黑白名单（内置兜底）">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="白名单 IP">
          <div class="w-full">
            <NInput v-model:value="wlIpText" type="textarea" :rows="2" placeholder="每行一个 IP 或 CIDR，如 127.0.0.1、10.0.0.0/8（命中直接放行）" />
          </div>
        </NFormItem>
        <NFormItem label="白名单 URL">
          <div class="w-full">
            <NInput v-model:value="wlUrlText" type="textarea" :rows="2" placeholder="每行一个正则，如 /favicon\\.ico（命中跳过规则检测）" />
          </div>
        </NFormItem>
        <NFormItem label="白名单 UA">
          <div class="w-full">
            <NInput v-model:value="wlUaText" type="textarea" :rows="2" placeholder="每行一个正则（命中跳过规则检测）" />
          </div>
        </NFormItem>
        <NFormItem label="黑名单 IP">
          <div class="w-full">
            <NInput v-model:value="blIpText" type="textarea" :rows="2" placeholder="每行一个 IP 或 CIDR（命中直接拦截）" />
          </div>
        </NFormItem>
        <NFormItem label="黑名单 URL">
          <div class="w-full">
            <NInput v-model:value="blUrlText" type="textarea" :rows="2" placeholder="每行一个正则（命中直接拦截）" />
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
              <NRadio value="file" label="本地文件" />
            </NSpace>
          </NRadioGroup>
        </NFormItem>
        <NFormItem v-if="cfg.log.backend === 'file'" label="文件目录">
          <NInput v-model:value="cfg.log.dir" class="w-80" placeholder="/var/log/waf" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">按天分文件 waf_YYYYMMDD.log</span>
        </NFormItem>
        <NFormItem v-if="cfg.log.backend === 'redis'" label="事件队列键">
          <NInput v-model:value="cfg.log.redis_key" class="w-80" placeholder="waf:event:list" />
        </NFormItem>
        <NFormItem label="格式">
          <NRadioGroup v-model:value="cfg.log.format">
            <NSpace>
              <NRadio value="json" label="JSON" />
              <NRadio value="plain" label="纯文本" />
            </NSpace>
          </NRadioGroup>
        </NFormItem>
        <NFormItem label="级别">
          <NSelect
            v-model:value="cfg.log.level"
            :options="['debug', 'info', 'warn', 'error'].map(v => ({ label: v, value: v }))"
            class="w-32"
          />
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper" v-if="loaded" title="全量流量记录">
      <NForm label-placement="left" label-width="140">
        <NFormItem label="记录全量流量">
          <NSwitch v-model:value="cfg.traffic_log.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">每个请求上报一条记录（含命中标记），用于「流量」页检索分析</span>
        </NFormItem>
        <NFormItem label="保留天数">
          <NInputNumber v-model:value="cfg.traffic_log.retention_days" :min="1" :max="365" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">后台按此天数自动清理过期流量记录</span>
        </NFormItem>
      </NForm>
    </NCard>

    <div v-if="loaded">
      <NButton type="primary" :loading="saving" @click="save">保存全部配置</NButton>
    </div>
  </div>
</template>
