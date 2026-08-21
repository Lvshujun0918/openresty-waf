<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NInputNumber, NPopconfirm, NSelect, NSpace, NTag } from 'naive-ui';
import { fetchConfig, saveConfig } from '@/service/api';

// 引擎规则分组（与攻击事件 group 对应）+ 自定义
const GROUP_OPTIONS = [
  { label: 'SQL 注入', value: 'sqli' },
  { label: 'XSS 跨站', value: 'xss' },
  { label: '远程执行', value: 'rce' },
  { label: '文件包含', value: 'lfi' },
  { label: 'SSRF', value: 'ssrf' },
  { label: '协议异常', value: 'protocol' },
  { label: '信息泄露', value: 'leak' },
  { label: '扫描器', value: 'scanner' },
  { label: '自定义规则', value: 'custom' },
  { label: '爬虫/客户端', value: 'crawler' },
  { label: 'CC 限流', value: 'cc' },
  { label: '触发规则拦截', value: 'trigger' },
  { label: '上传检测', value: 'upload' },
  { label: '指纹拦截', value: 'fingerprint' },
  { label: '响应检测', value: 'response' }
];

interface PageItem {
  key: string; // 前端唯一标识（非持久化）
  group: string;
  name: string;
  html: string;
}

const saving = ref(false);
const loading = ref(true);
const defaultHtml = ref('');
const defaultStatus = ref(403);
const pages = ref<PageItem[]>([]);
const selected = ref<string | 'default'>('default');
let rawConfig: Record<string, unknown> = {};
let seq = 0;

const DEFAULT_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问已被拦截</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    font-family: "PingFang SC", "Helvetica Neue", "Microsoft YaHei", Arial, sans-serif;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px; color: #334155;
  }
  .card {
    background: #ffffff; border-radius: 16px;
    width: 92%; max-width: 520px; padding: 48px 40px 36px;
    text-align: center; position: relative;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35);
  }
  .icon {
    width: 76px; height: 76px; margin: 0 auto 24px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 50%; background: #fef2f2; border: 1px solid #fecaca;
  }
  .icon svg { width: 42px; height: 42px; }
  h1 { font-size: 22px; font-weight: 600; color: #0f172a; margin-bottom: 12px; }
  .desc { font-size: 14px; color: #64748b; line-height: 1.9; margin-bottom: 26px; }
  .meta {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 14px 18px; font-size: 13px; color: #94a3b8; text-align: left;
    display: grid; gap: 8px; margin-bottom: 26px;
  }
  .meta .row { display: flex; gap: 8px; }
  .meta .k { color: #64748b; flex-shrink: 0; min-width: 72px; }
  .meta .v { color: #334155; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .footer { font-size: 12px; color: #94a3b8; }
  .footer b { color: #64748b; font-weight: 500; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M12 3 2 20h20L12 3z" fill="#ef4444"/>
        <path d="M13 9.5h-2V15h2V9.5zm0 7.5h-2v2h2v-2z" fill="#ffffff"/>
      </svg>
    </div>
    <h1>访问已被拦截</h1>
    <p class="desc">检测到您的请求存在恶意行为或异常特征，已由安全防火墙拦截。如有疑问请联系网站管理员。</p>
    <div class="meta">
      <div class="row"><span class="k">来源 IP</span><span class="v">{ip}</span></div>
      <div class="row"><span class="k">请求地址</span><span class="v">{uri}</span></div>
      <div class="row"><span class="k">拦截原因</span><span class="v">{group}</span></div>
      <div class="row"><span class="k">事件编号</span><span class="v">{req_id}</span></div>
    </div>
    <div class="footer">Web Application Firewall 安全防护 · <b>请求已被拦截</b></div>
  </div>
</body>
</html>`;

const DEFAULT_GROUP_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>访问被拒绝</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px;color:#444}
h1{font-size:36px;color:#c0392b}.code{font-size:72px;color:#eee}</style>
</head><body><div class="code">403</div>
<h1>检测到异常请求</h1>
<p>您的访问因触发安全策略被拦截，如有疑问请联系网站管理员。</p>
</body></html>`;

function groupLabel(g: string) {
  return GROUP_OPTIONS.find(o => o.value === g)?.label || g;
}

const selectedPage = computed(() => {
  if (selected.value === 'default') return null;
  return pages.value.find(p => p.key === selected.value) ?? null;
});

async function load() {
  loading.value = true;
  try {
    const res = await fetchConfig();
    rawConfig = res.data?.config ?? {};
    const block = (rawConfig.block as Record<string, unknown>) ?? {};
    defaultHtml.value = String(block.html || DEFAULT_HTML);
    defaultStatus.value = Number(block.status) || 403;
    const ps = (block.pages as Array<Record<string, unknown>>) ?? [];
    pages.value = ps
      .filter(p => p && p.group)
      .map(p => ({
        key: `k${seq++}`,
        group: String(p.group),
        name: String(p.name || p.group),
        html: String(p.html || '')
      }));
    if (pages.value.length > 0) selected.value = pages.value[0].key;
  } finally {
    loading.value = false;
  }
}
onMounted(load);

function addPage() {
  const group = 'sqli';
  const name = groupLabel(group);
  const item: PageItem = { key: `k${seq++}`, group, name, html: DEFAULT_GROUP_HTML };
  pages.value.push(item);
  selected.value = item.key;
}

function removePage(item: PageItem) {
  pages.value = pages.value.filter(p => p.key !== item.key);
  if (selected.value === item.key) {
    selected.value = pages.value.length ? pages.value[0].key : 'default';
  }
}

function duplicateHtml(item: PageItem) {
  const src = selectedPage.value;
  if (src) {
    item.html = src.html;
  }
}

const previewHtml = computed(() => {
  const p = selectedPage.value;
  const html = p ? p.html : defaultHtml.value;
  return html || DEFAULT_HTML;
});

async function save() {
  saving.value = true;
  try {
    const block = (rawConfig.block as Record<string, unknown>) ?? {};
    block.status = defaultStatus.value;
    block.html = defaultHtml.value || DEFAULT_HTML;
    block.pages = pages.value.map(({ group, name, html }) => ({ group, name, html }));
    rawConfig.block = block;
    await saveConfig(rawConfig);
    window.$message?.success('已保存并下发引擎（5 秒内热更新生效）');
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">拦截页面</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          按命中规则分组显示不同拦截页面；未配置分组的请求使用「默认兜底页」。
          页面支持任意 HTML，占位符 {ip} {uri} {group} {req_id} 将展示来源 IP、请求地址、命中分组与事件编号。
        </p>
      </div>
      <NSpace>
        <NButton secondary :loading="saving" @click="load">重置</NButton>
        <NButton type="primary" :loading="saving" @click="save">保存并下发</NButton>
      </NSpace>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <div class="grid grid-cols-[300px_1fr] gap-4">
        <!-- 左：分组列表 -->
        <div class="space-y-2">
          <div class="mb-1 flex items-center justify-between">
            <span class="text-sm font-medium">拦截分组</span>
            <NButton size="tiny" type="primary" ghost @click="addPage">+ 新增分组</NButton>
          </div>
          <div
            class="flex cursor-pointer items-center justify-between rounded-lg border border-[rgb(229,229,229)] px-3 py-2 transition hover:border-[#2563eb]"
            :class="selected === 'default' ? 'border-[#2563eb] bg-[rgb(37,99,235,0.06)]' : ''"
            @click="selected = 'default'"
          >
            <div class="flex items-center gap-2">
              <NTag size="tiny" bordered type="info">兜底</NTag>
              <span class="text-sm">默认兜底页</span>
            </div>
            <span class="text-xs text-[rgb(125,125,125)]">{{ defaultStatus }}</span>
          </div>
          <div
            v-for="p in pages"
            :key="p.key"
            class="flex cursor-pointer items-center justify-between rounded-lg border border-[rgb(229,229,229)] px-3 py-2 transition hover:border-[#2563eb]"
            :class="selected === p.key ? 'border-[#2563eb] bg-[rgb(37,99,235,0.06)]' : ''"
            @click="selected = p.key"
          >
            <div class="flex min-w-0 items-center gap-2">
              <NTag size="tiny" bordered type="warning">{{ groupLabel(p.group) }}</NTag>
              <span class="truncate text-sm">{{ p.name || groupLabel(p.group) }}</span>
            </div>
            <NPopconfirm negative-text="取消" positive-text="删除" @positive-click="removePage(p)">
              <template #trigger>
                <NButton size="tiny" quaternary type="error">×</NButton>
              </template>
              删除该分组拦截页？
            </NPopconfirm>
          </div>
          <NEmpty v-if="!pages.length" description="暂无自定义分组，可点击上方「新增分组」" class="py-6" :show="false" />
        </div>

        <!-- 右：配置 + 预览 -->
        <div v-if="!loading" class="space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <NCard :bordered="false" class="card-wrapper" title="页面配置">
              <template v-if="selected === 'default'">
                <NForm label-placement="left" label-width="80">
                  <NFormItem label="状态码">
                    <NInputNumber v-model:value="defaultStatus" :min="400" :max="599" style="width: 120px" />
                  </NFormItem>
                  <NFormItem label="页面标题">
                    <NInput
                      v-model:value="defaultHtml"
                      type="textarea"
                      :rows="14"
                      placeholder="默认兜底拦截页面 HTML"
                    />
                  </NFormItem>
                </NForm>
              </template>
              <template v-else>
                <NForm label-placement="left" label-width="80">
                  <NFormItem label="分组">
                    <NSelect
                      :value="selectedPage!.group"
                      :options="GROUP_OPTIONS"
                      @update:value="v => (selectedPage!.group = v)"
                    />
                  </NFormItem>
                  <NFormItem label="名称">
                    <NInput v-model:value="selectedPage!.name" placeholder="如 爬虫拦截页" />
                  </NFormItem>
                  <NFormItem label="HTML">
                    <div class="w-full space-y-2">
                      <div class="flex justify-end">
                        <NButton size="tiny" secondary @click="duplicateHtml(selectedPage!)">从当前页复制</NButton>
                      </div>
                      <NInput v-model:value="selectedPage!.html" type="textarea" :rows="11" placeholder="该分组的拦截页面 HTML" />
                    </div>
                  </NFormItem>
                </NForm>
              </template>
            </NCard>

            <NCard :bordered="false" class="card-wrapper" title="实时预览">
              <div class="h-[560px] w-full overflow-hidden rounded-lg border border-[rgb(229,229,229)] bg-white">
                <iframe :srcdoc="previewHtml" class="h-full w-full" sandbox="" />
              </div>
            </NCard>
          </div>
        </div>
      </div>
    </NCard>
  </div>
</template>