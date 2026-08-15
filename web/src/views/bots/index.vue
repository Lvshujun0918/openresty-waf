<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
import {
  useMessage,
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NSelect,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  NStatistic,
  NGrid,
  NGi
} from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import Ja4Identify from '@/components/custom/Ja4Identify.vue';
import { replayRequest } from '@/service/api';
import type { ECOption } from '@/hooks/common/echarts';
import {
  blacklistBotLog,
  consumeBotLogs,
  createJa4Profile,
  exportJa4Malware,
  deleteJa4Profile,
  fetchBotLogDetail,
  fetchJa4Profiles,
  createBotFingerprint,
  createBotProfile,
  deleteBotFingerprint,
  deleteBotProfile,
  fetchBotFingerprints,
  fetchBotLogs,
  fetchBotProfiles,
  fetchBotStats,
  fetchBotTop,
  fetchBotTrend,
  updateJa4Profile,
  updateBotFingerprint,
  updateBotProfile
} from '@/service/api';

const message = useMessage();

// —— 统计 ——
const stats = ref({ total: 0, real: 0, fake: 0, tools: 0, malicious_ip: 0, malicious_fp: 0 });
const topIPs = ref<{ key: string; count: number }[]>([]);
const topProfiles = ref<{ key: string; count: number }[]>([]);
const trendPoints = ref<{ date: string; total: number; fake: number }[]>([]);

// —— 记录 ——
const logs = ref<Api.Waf.BotLog[]>([]);
const logTotal = ref(0);
const logPage = ref(1);
const logPageSize = ref(20);
const logFilter = ref({ profile: '', client_ip: '', fake: '', malicious: '', unknown_ja4: '' });

// —— 画像库 ——
const profiles = ref<Api.Waf.BotProfile[]>([]);
const showProfileModal = ref(false);
const editingProfile = ref<Partial<Api.Waf.BotProfile>>({ engine: true, enabled: true });
const profileEngine = ref(1); // NSelect 用数字值（0/1），保存时转 bool

// —— 恶意指纹库 ——
const fingerprints = ref<Api.Waf.BotFingerprint[]>([]);
const showFpModal = ref(false);
const editingFp = ref<Partial<Api.Waf.BotFingerprint>>({ match: 'exact', enabled: true });

function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

// —— 趋势图 ——
const trendOption = (): ECOption => ({
  tooltip: { trigger: 'axis' },
  legend: { data: ['爬虫请求', '虚假爬虫'], top: 0 },
  grid: { left: 40, right: 16, top: 32, bottom: 8 },
  xAxis: { type: 'category', data: trendPoints.value.map(p => p.date.slice(5)) },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    {
      name: '爬虫请求',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#2563eb' },
      areaStyle: { color: 'rgba(37,99,235,0.12)' },
      data: trendPoints.value.map(p => p.total)
    },
    {
      name: '虚假爬虫',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#ef4444' },
      areaStyle: { color: 'rgba(239,68,68,0.1)' },
      data: trendPoints.value.map(p => p.fake)
    }
  ]
});
const { domRef: trendRef, updateOptions: updateTrend } = useEcharts(trendOption);

async function loadStats() {
  const [st, tip, tpr, tr] = await Promise.all([
    fetchBotStats().catch(() => ({ data: { total: 0, real: 0, fake: 0, tools: 0, malicious_ip: 0, malicious_fp: 0 } })),
    fetchBotTop('ip', 8).catch(() => ({ data: { items: [] as { key: string; count: number }[] } })),
    fetchBotTop('profile', 8).catch(() => ({ data: { items: [] as { key: string; count: number }[] } })),
    fetchBotTrend(7).catch(() => ({ data: { items: [] as { date: string; total: number; fake: number }[] } }))
  ]);
  stats.value = st.data ?? { total: 0, real: 0, fake: 0, tools: 0, malicious_ip: 0, malicious_fp: 0 };
  topIPs.value = tip.data?.items ?? [];
  topProfiles.value = tpr.data?.items ?? [];
  trendPoints.value = tr.data?.items ?? [];
  updateTrend(() => trendOption());
}

async function loadLogs() {
  const res = await fetchBotLogs({
    page: logPage.value,
    page_size: logPageSize.value,
    profile: logFilter.value.profile,
    client_ip: logFilter.value.client_ip,
    fake: logFilter.value.fake,
    malicious: logFilter.value.malicious,
    unknown_ja4: logFilter.value.unknown_ja4
  });
  logs.value = res.data?.items ?? [];
  logTotal.value = res.data?.total ?? 0;
}

async function loadProfiles() {
  const res = await fetchBotProfiles().catch(() => ({ data: [] as Api.Waf.BotProfile[] }));
  profiles.value = res.data ?? [];
}

async function loadFingerprints() {
  const res = await fetchBotFingerprints().catch(() => ({ data: [] as Api.Waf.BotFingerprint[] }));
  fingerprints.value = res.data ?? [];
}

function load() {
  loadStats();
  loadLogs();
  loadProfiles();
  loadFingerprints();
  loadJa4Profiles();
}
onMounted(load);

// —— 画像库操作 ——
async function saveProfile() {
  const data = { ...editingProfile.value, engine: profileEngine.value === 1 };
  if (data.id) {
    await updateBotProfile(data.id, data);
  } else {
    await createBotProfile(data);
  }
  message.success('已保存并下发引擎（5 秒内热更新生效）');
  showProfileModal.value = false;
  loadProfiles();
}

function editProfile(row?: Api.Waf.BotProfile) {
  editingProfile.value = row ? { ...row } : { engine: true, enabled: true, sort_order: 100 };
  profileEngine.value = editingProfile.value.engine ? 1 : 0;
  showProfileModal.value = true;
}

// —— 指纹库操作 ——
async function saveFingerprint() {
  const data = { ...editingFp.value };
  if (data.id) {
    await updateBotFingerprint(data.id, data);
  } else {
    await createBotFingerprint(data);
  }
  message.success('已保存并下发引擎（5 秒内热更新生效）');
  showFpModal.value = false;
  loadFingerprints();
}

function editFingerprint(row?: Api.Waf.BotFingerprint) {
  editingFp.value = row ? { ...row } : { match: 'exact', enabled: true };
  showFpModal.value = true;
}

// —— JA4 客户端库 ——
const ja4Profiles = ref<Api.Waf.Ja4Profile[]>([]);
const showJa4Modal = ref(false);
const editingJa4 = ref<Partial<Api.Waf.Ja4Profile>>({ category: 'tool', enabled: true });

async function loadJa4Profiles() {
  const res = await fetchJa4Profiles().catch(() => ({ data: [] as Api.Waf.Ja4Profile[] }));
  ja4Profiles.value = res.data ?? [];
}

async function saveJa4Profile() {
  const data = { ...editingJa4.value };
  if (data.id) {
    await updateJa4Profile(data.id, data);
  } else {
    await createJa4Profile(data);
  }
  message.success('已保存');
  showJa4Modal.value = false;
  loadJa4Profiles();
}

function editJa4Profile(row?: Api.Waf.Ja4Profile) {
  editingJa4.value = row ? { ...row } : { category: 'tool', enabled: true };
  showJa4Modal.value = true;
}

async function doExportJa4() {
  const res = await exportJa4Malware();
  const url = URL.createObjectURL(res.data as unknown as Blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ja4-malware-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

const ja4CatMeta: Record<string, { label: string; type: 'error' | 'info' | 'warning' | 'default' }> = {
  malware: { label: '恶意软件', type: 'error' },
  browser: { label: '浏览器', type: 'info' },
  tool: { label: '工具/库', type: 'warning' },
  other: { label: '其他', type: 'default' }
};

const ja4Columns = [
  { title: '客户端', key: 'name', minWidth: 140 },
  {
    title: '分类',
    key: 'category',
    width: 100,
    render: (row: Api.Waf.Ja4Profile) =>
      h(NTag, { size: 'small', bordered: false, type: ja4CatMeta[row.category]?.type || 'default' },
        { default: () => ja4CatMeta[row.category]?.label || row.category })
  },
  { title: 'JA4', key: 'ja4', ellipsis: { tooltip: true }, render: (row: Api.Waf.Ja4Profile) => h('span', { class: 'font-mono text-xs' }, row.ja4) },
  { title: 'JA4_ac', key: 'ac_prefix', width: 110, render: (row: Api.Waf.Ja4Profile) => h('span', { class: 'font-mono text-[11px] text-[rgb(125,125,125)]' }, row.ac_prefix || '-') },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '操作',
    key: 'action',
    width: 120,
    render: (row: Api.Waf.Ja4Profile) =>
      h('div', { class: 'flex gap-2' }, [
        h(NButton, { size: 'small', quaternary: true, onClick: () => editJa4Profile(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => deleteJa4Profile(row.id).then(loadJa4Profiles) },
          { trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }), default: () => '确认删除？' }
        )
      ])
  }
];

// —— 表格列 ——
const profileColumns = [
  { title: '名称', key: 'name', width: 140, render: (row: Api.Waf.BotProfile) => h('span', { class: 'font-medium' }, row.name) },
  {
    title: '类型',
    key: 'engine',
    width: 110,
    render: (row: Api.Waf.BotProfile) =>
      row.engine
        ? h(NTag, { type: 'warning', size: 'small', bordered: false }, { default: () => '搜索引擎（IP 验证）' })
        : h(NTag, { type: 'default', size: 'small', bordered: false }, { default: () => '工具/采集' })
  },
  { title: 'UA 正则', key: 'ua', ellipsis: { tooltip: true } },
  {
    title: '启用',
    key: 'enabled',
    width: 80,
    render: (row: Api.Waf.BotProfile) =>
      h(NSwitch, { value: row.enabled, onUpdateValue: v => updateBotProfile(row.id, { ...row, enabled: v }).then(loadProfiles) })
  },
  {
    title: '操作',
    key: 'action',
    width: 120,
    render: (row: Api.Waf.BotProfile) =>
      h('div', { class: 'flex gap-2' }, [
        h(NButton, { size: 'small', quaternary: true, onClick: () => editProfile(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => deleteBotProfile(row.id).then(loadProfiles) },
          { trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }), default: () => '确认删除该画像？' }
        )
      ])
  }
];

const fpColumns = [
  { title: '名称', key: 'name', width: 140 },
  { title: '指纹值', key: 'value', ellipsis: { tooltip: true }, render: (row: Api.Waf.BotFingerprint) => h('span', { class: 'font-mono text-xs' }, row.value) },
  { title: '匹配方式', key: 'match', width: 90, render: (row: Api.Waf.BotFingerprint) => (row.match === 'regex' ? '正则' : '精确') },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '启用',
    key: 'enabled',
    width: 80,
    render: (row: Api.Waf.BotFingerprint) =>
      h(NSwitch, { value: row.enabled, onUpdateValue: v => updateBotFingerprint(row.id, { ...row, enabled: v }).then(loadFingerprints) })
  },
  {
    title: '操作',
    key: 'action',
    width: 120,
    render: (row: Api.Waf.BotFingerprint) =>
      h('div', { class: 'flex gap-2' }, [
        h(NButton, { size: 'small', quaternary: true, onClick: () => editFingerprint(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => deleteBotFingerprint(row.id).then(loadFingerprints) },
          { trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }), default: () => '确认删除该指纹？' }
        )
      ])
  }
];

const logColumns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.BotLog) => fmtTime(row.time) },
  {
    title: '来源',
    key: 'client_ip',
    minWidth: 140,
    render: (row: Api.Waf.BotLog) =>
      h('div', { class: 'space-y-0.5' }, [
        h('div', { class: 'font-mono text-xs' }, row.client_ip),
        h('div', { class: 'text-[11px] text-[rgb(125,125,125)]' }, [row.country, row.province, row.city].filter(Boolean).join(' '))
      ])
  },
  {
    title: '识别结果',
    key: 'profile',
    width: 150,
    render: (row: Api.Waf.BotLog) =>
      h('div', { class: 'flex flex-wrap gap-1' }, [
        h(NTag, { size: 'small', bordered: false, type: 'default' }, { default: () => row.profile || '-' }),
        row.fake ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '虚假' }) : null,
        row.engine && !row.fake ? h(NTag, { size: 'small', type: 'success', bordered: false }, { default: () => '真实' }) : null,
        row.malicious_ip ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '恶意IP' }) : null,
        row.malicious_fp ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '恶意指纹' }) : null
      ])
  },
  {
    title: '客户端',
    key: 'client_name',
    width: 150,
    render: (row: Api.Waf.BotLog) => {
      if (!row.ja4) return h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '-');
      if (row.client_name) {
        const catMeta: Record<string, { label: string; type: 'error' | 'info' | 'warning' }> = {
          malware: { label: '恶意', type: 'error' },
          browser: { label: '浏览器', type: 'info' },
          tool: { label: '工具', type: 'warning' }
        };
        const cat = row.client_category || 'other';
        return h('div', { class: 'flex flex-wrap items-center gap-1' }, [
          h(NTag, { size: 'small', bordered: false, type: catMeta[cat]?.type || 'default' }, { default: () => catMeta[cat]?.label || cat }),
          h('span', { class: 'text-xs' }, row.client_name),
          row.ja4_match === 'ac'
            ? h(NTag, { size: 'tiny', bordered: false, type: 'warning' }, { default: () => '疑似轮换' })
            : null
        ]);
      }
      return h(NTag, { size: 'small', bordered: false, type: 'default' }, { default: () => '未知' });
    }
  },
  { title: 'UA', key: 'ua', ellipsis: { tooltip: true }, render: (row: Api.Waf.BotLog) => h('span', { class: 'text-xs' }, row.ua) },
  {
    title: '指纹',
    key: 'ja4',
    width: 130,
    render: (row: Api.Waf.BotLog) =>
      h('div', { class: 'space-y-0.5' }, [
        row.ja4
          ? h('div', { class: 'flex items-center gap-1' }, [
              h(NTag, { size: 'tiny', bordered: false, type: 'info' }, { default: () => 'JA4' }),
              h('span', { class: 'font-mono text-[11px] text-[rgb(125,125,125)]', title: row.ja4 }, row.ja4.slice(0, 10) + '…')
            ])
          : null,
        h('span', { class: 'font-mono text-[11px] text-[rgb(125,125,125)]', title: row.fingerprint }, 'http ' + row.fingerprint.slice(0, 8))
      ])
  },
  { title: '请求', key: 'uri', ellipsis: { tooltip: true }, render: (row: Api.Waf.BotLog) => h('span', { class: 'text-xs' }, `${row.method} ${row.host}${row.uri}`) },
  { title: '状态', key: 'status', width: 70 },
  {
    title: '操作',
    key: 'action',
    width: 160,
    render: (row: Api.Waf.BotLog) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openDetail(row.id) }, { default: () => '详情' }),
        h(
          NPopconfirm,
          {
            onPositiveClick: async () => {
              await blacklistBotLog(row.id);
              message.success('指纹已加入恶意指纹库并下发，同指纹请求将被拦截');
            }
          },
          {
            trigger: () =>
              h(
                NButton,
                { size: 'small', quaternary: true, type: 'error', disabled: !row.ja4 && !row.fingerprint },
                { default: () => '指纹拉黑' }
              ),
            default: () => '将该请求的 TLS 指纹加入恶意指纹库？同指纹客户端将被拦截'
          }
        )
      ])
  }
];

async function consume() {
  const res = await consumeBotLogs();
  message.success(`已消费 ${res.data?.consumed ?? 0} 条`);
  loadLogs();
  loadStats();
}

// —— 详情弹窗（与攻击事件详情一致：基本信息 + 请求头 + 请求体 + JA4） ——
const detailOpen = ref(false);
const detailLoading = ref(false);
const detail = ref<Api.Waf.BotLog | null>(null);
const detailHeaders = ref<{ name: string; value: string }[]>([]);

async function openDetail(id: number) {
  detailOpen.value = true;
  detailLoading.value = true;
  detail.value = null;
  detailHeaders.value = [];
  try {
    const res = await fetchBotLogDetail(id);
    detail.value = res.data ?? null;
    try {
      const parsed = JSON.parse(detail.value?.headers || '[]');
      detailHeaders.value = Array.isArray(parsed) ? parsed : [];
    } catch {
      detailHeaders.value = [];
    }
  } finally {
    detailLoading.value = false;
  }
}
function closeDetail() {
  detailOpen.value = false;
  detail.value = null;
}

// —— 重放检测 ——
const replaying = ref(false);
const replayHits = ref<{ rule_id: string; name: string; group: string; msg: string; severity: number }[]>([]);
const replayOpen = ref(false);

function parseHeaderMap(headers: string): Record<string, string> {
  const out: Record<string, string> = {};
  try {
    const list = JSON.parse(headers || '[]') as { name: string; value: string }[];
    for (const h of list) out[h.name] = h.value;
  } catch {
    /* 忽略 */
  }
  return out;
}

async function doReplay() {
  if (!detail.value) return;
  replaying.value = true;
  try {
    const hmap = parseHeaderMap(detail.value.headers || '');
    const res = await replayRequest({
      method: detail.value.method || 'GET',
      uri: detail.value.uri || '/',
      body: detail.value.body || '',
      content_type: hmap['content-type'] || 'application/x-www-form-urlencoded',
      headers: hmap,
      cookies: hmap['cookie'] || ''
    });
    replayHits.value = res.data?.hits ?? [];
    replayOpen.value = true;
  } finally {
    replaying.value = false;
  }
}
const botHeaderColumns = [
  { title: '名称', key: 'name', width: 180, render: (row: { name: string }) => h('span', { class: 'font-mono text-xs' }, row.name) },
  { title: '值', key: 'value', render: (row: { value: string }) => h('span', { class: 'break-all font-mono text-xs text-[rgb(125,125,125)]' }, row.value) }
];
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">爬虫管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          UA 画像 + 搜索引擎 IP 段验证 + HTTP 指纹比对：识别真实爬虫与虚假爬虫（UA 声称搜索引擎但来源 IP 不匹配）
        </p>
      </div>
      <NButton secondary @click="consume">消费 Redis 队列</NButton>
    </div>

    <NTabs type="line" default-value="stats">
      <NTabPane name="stats" tab="统计总览">
        <NGrid :x-gap="16" :y-gap="16" cols="s:1 m:3">
          <NGi>
            <NCard :bordered="false" class="card-wrapper">
              <NStatistic label="爬虫请求总数" :value="stats.total" />
            </NCard>
          </NGi>
          <NGi>
            <NCard :bordered="false" class="card-wrapper">
              <NStatistic label="真实搜索引擎爬虫" :value="stats.real">
                <template #suffix><span class="text-sm text-[rgb(125,125,125)]">· 工具/采集 {{ stats.tools }}</span></template>
              </NStatistic>
            </NCard>
          </NGi>
          <NGi>
            <NCard :bordered="false" class="card-wrapper">
              <NStatistic label="虚假爬虫（伪造 UA）" :value="stats.fake">
                <template #suffix><span class="text-sm text-[rgb(125,125,125)]">· 恶意IP {{ stats.malicious_ip }} · 恶意指纹 {{ stats.malicious_fp }}</span></template>
              </NStatistic>
            </NCard>
          </NGi>
        </NGrid>

        <NCard :bordered="false" class="card-wrapper" title="爬虫趋势（近 7 天）">
          <div ref="trendRef" class="h-56 w-full" />
        </NCard>

        <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
          <NGi span="24 s:24 m:12">
            <NCard :bordered="false" class="card-wrapper h-full" title="爬虫来源 IP Top 8">
              <div class="space-y-2">
                <div v-for="(x, i) in topIPs" :key="x.key" class="flex items-center gap-3">
                  <span class="w-4 text-right text-xs text-[rgb(125,125,125)]">{{ i + 1 }}</span>
                  <span class="min-w-0 flex-1 truncate font-mono text-xs">{{ x.key }}</span>
                  <span class="text-xs font-medium">{{ x.count }}</span>
                </div>
                <NEmpty v-if="!topIPs.length" description="暂无数据" class="py-6" />
              </div>
            </NCard>
          </NGi>
          <NGi span="24 s:24 m:12">
            <NCard :bordered="false" class="card-wrapper h-full" title="爬虫画像命中 Top 8">
              <div class="space-y-2">
                <div v-for="(x, i) in topProfiles" :key="x.key" class="flex items-center gap-3">
                  <span class="w-4 text-right text-xs text-[rgb(125,125,125)]">{{ i + 1 }}</span>
                  <span class="min-w-0 flex-1 truncate text-xs">{{ x.key }}</span>
                  <span class="text-xs font-medium">{{ x.count }}</span>
                </div>
                <NEmpty v-if="!topProfiles.length" description="暂无数据" class="py-6" />
              </div>
            </NCard>
          </NGi>
        </NGrid>
      </NTabPane>

      <NTabPane name="logs" tab="访问记录">
        <NCard :bordered="false" class="card-wrapper">
          <div class="mb-3 flex flex-wrap gap-3">
            <NInput v-model:value="logFilter.profile" placeholder="画像名过滤" clearable style="width: 140px" @keyup.enter="logPage = 1; loadLogs()" />
            <NInput v-model:value="logFilter.client_ip" placeholder="来源 IP" clearable style="width: 150px" @keyup.enter="logPage = 1; loadLogs()" />
            <NSelect v-model:value="logFilter.fake" placeholder="虚假爬虫" clearable style="width: 120px" :options="[{ label: '虚假', value: '1' }]" @update:value="logPage = 1; loadLogs()" />
            <NSelect v-model:value="logFilter.malicious" placeholder="恶意来源" clearable style="width: 120px" :options="[{ label: '恶意IP/指纹', value: '1' }]" @update:value="logPage = 1; loadLogs()" />
            <NSelect v-model:value="logFilter.unknown_ja4" placeholder="未知 JA4" clearable style="width: 110px" :options="[{ label: '未知指纹', value: '1' }]" @update:value="logPage = 1; loadLogs()" />
            <NButton size="small" type="primary" @click="logPage = 1; loadLogs()">查询</NButton>
          </div>
          <NDataTable
            :columns="logColumns"
            :data="logs"
            :pagination="{
              page: logPage,
              pageSize: logPageSize,
              itemCount: logTotal,
              onChange: p => { logPage = p; loadLogs(); }
            }"
            size="small"
            :bordered="false"
          />
        </NCard>
      </NTabPane>

      <NTabPane name="profiles" tab="爬虫画像库">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NButton type="primary" size="small" @click="editProfile()">新建画像</NButton>
          </template>
          <NDataTable :columns="profileColumns" :data="profiles" size="small" :bordered="false" />
        </NCard>
      </NTabPane>

      <NTabPane name="ja4" tab="JA4 客户端库">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NButton secondary size="small" class="mr-2" @click="doExportJa4">导出恶意情报</NButton>
            <NButton type="primary" size="small" @click="editJa4Profile()">新增</NButton>
          </template>
          <p class="mb-3 text-xs text-[rgb(125,125,125)]">
            内置 FoxIO 已知客户端指纹（浏览器/工具/恶意软件）：恶意类命中自动加入恶意指纹库拦截；详情页 JA4 将显示识别结果
          </p>
          <NDataTable :columns="ja4Columns" :data="ja4Profiles" size="small" :bordered="false" />
        </NCard>
      </NTabPane>
      <NTabPane name="fingerprints" tab="恶意指纹库">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NButton type="primary" size="small" @click="editFingerprint()">新建指纹</NButton>
          </template>
          <NDataTable :columns="fpColumns" :data="fingerprints" size="small" :bordered="false" />
        </NCard>
      </NTabPane>
    </NTabs>

    <!-- 画像编辑弹窗 -->
    <NModal v-model:show="showProfileModal" preset="card" :title="editingProfile.id ? '编辑画像' : '新建画像'" style="width: 560px">
      <NForm label-placement="left" label-width="100">
        <NFormItem label="名称"><NInput v-model:value="editingProfile.name" placeholder="如 Googlebot" /></NFormItem>
        <NFormItem label="类型">
          <NSelect
            v-model:value="profileEngine"
            :options="[
              { label: '搜索引擎（需 IP 段验证，IP 不匹配判定虚假爬虫）', value: 1 },
              { label: '工具/采集类（UA 命中直接识别）', value: 0 }
            ]"
          />
        </NFormItem>
        <NFormItem label="UA 正则"><NInput v-model:value="editingProfile.ua" placeholder="PCRE 正则，如 Googlebot|Google-InspectionTool" /></NFormItem>
        <NFormItem v-if="profileEngine === 1" label="IP 网段">
          <NInput v-model:value="editingProfile.ips" placeholder="CIDR 数组 JSON，如 [&quot;66.249.64.0/19&quot;,&quot;64.233.160.0/19&quot;]" />
        </NFormItem>
        <NFormItem label="排序"><NInputNumber v-model:value="editingProfile.sort_order" :min="0" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="editingProfile.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showProfileModal = false">取消</NButton>
          <NButton type="primary" @click="saveProfile">保存并下发</NButton>
        </div>
      </template>
    </NModal>

    <!-- 指纹编辑弹窗 -->
    <NModal v-model:show="showFpModal" preset="card" :title="editingFp.id ? '编辑指纹' : '新建指纹'" style="width: 520px">
      <NForm label-placement="left" label-width="100">
        <NFormItem label="名称"><NInput v-model:value="editingFp.name" placeholder="如 恶意采集工具A" /></NFormItem>
        <NFormItem label="指纹值"><NInput v-model:value="editingFp.value" placeholder="32 位指纹哈希（可从爬虫记录中复制）" /></NFormItem>
        <NFormItem label="匹配方式">
          <NSelect v-model:value="editingFp.match" :options="[{ label: '精确匹配', value: 'exact' }, { label: '正则匹配', value: 'regex' }]" />
        </NFormItem>
        <NFormItem label="描述"><NInput v-model:value="editingFp.description" placeholder="选填" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="editingFp.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showFpModal = false">取消</NButton>
          <NButton type="primary" @click="saveFingerprint">保存并下发</NButton>
        </div>
      </template>
    </NModal>

    <!-- JA4 客户端库编辑弹窗 -->
    <NModal v-model:show="showJa4Modal" preset="card" :title="editingJa4.id ? '编辑客户端' : '新增客户端'" style="width: 560px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="名称"><NInput v-model:value="editingJa4.name" placeholder="如 Chromium Browser / Sliver Agent" /></NFormItem>
        <NFormItem label="JA4"><NInput v-model:value="editingJa4.ja4" placeholder="如 t13d1516h2_8daaf6152771_02713d6af862" /></NFormItem>
        <NFormItem label="分类">
          <NSelect
            v-model:value="editingJa4.category"
            :options="[
              { label: '浏览器', value: 'browser' },
              { label: '工具/库', value: 'tool' },
              { label: '恶意软件', value: 'malware' },
              { label: '其他', value: 'other' }
            ]"
          />
        </NFormItem>
        <NFormItem label="描述"><NInput v-model:value="editingJa4.description" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="editingJa4.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showJa4Modal = false">取消</NButton>
          <NButton type="primary" @click="saveJa4Profile">保存</NButton>
        </div>
      </template>
    </NModal>

    <!-- 爬虫记录详情 -->
    <NModal
      v-model:show="detailOpen"
      preset="card"
      title="爬虫记录详情"
      class="w-[min(96vw,760px)]"
      :bordered="false"
      :style="{ borderRadius: '12px' }"
      @close="closeDetail"
    >
      <div v-if="detailLoading" class="py-10 text-center text-sm text-[rgb(125,125,125)]">加载中…</div>
      <div v-else-if="detail" class="space-y-5">
        <p class="font-mono text-[11px] text-[rgb(125,125,125)]">req_id: {{ detail.req_id || '-' }}</p>

        <!-- 基本信息 -->
        <div class="grid grid-cols-2 gap-x-6 gap-y-2.5 text-sm md:grid-cols-3">
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">时间</div>
            <div>{{ fmtTime(detail.time) }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">来源 IP</div>
            <div class="font-mono">{{ detail.client_ip }}</div>
          </div>
          <div v-if="detail.country">
            <div class="text-xs text-[rgb(125,125,125)]">归属地</div>
            <div>{{ [detail.country, detail.province, detail.city].filter(Boolean).join(' ') }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">识别结果</div>
            <div class="flex flex-wrap gap-1">
              <NTag size="small" bordered :type="detail.fake ? 'error' : detail.engine ? 'success' : 'default'">
                {{ detail.profile || '-' }}{{ detail.fake ? '（虚假）' : detail.engine ? '（真实）' : '' }}
              </NTag>
              <NTag v-if="detail.malicious_ip" size="small" type="error" bordered>恶意IP</NTag>
              <NTag v-if="detail.malicious_fp" size="small" type="error" bordered>恶意指纹</NTag>
            </div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">方法</div>
            <div>{{ detail.method || '-' }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">域名</div>
            <div>{{ detail.host || '-' }}</div>
          </div>
          <div v-if="detail.ja4" class="col-span-2 md:col-span-3">
            <div class="text-xs text-[rgb(125,125,125)]">JA4 指纹</div>
            <div class="flex items-center gap-2">
              <span class="font-mono text-xs" :title="detail.ja4">{{ detail.ja4 }}</span>
              <Ja4Identify :ja4="detail.ja4" />
            </div>
          </div>
          <div v-if="detail.ja4h">
            <div class="text-xs text-[rgb(125,125,125)]">JA4H 指纹</div>
            <div class="font-mono text-xs" :title="detail.ja4h">{{ detail.ja4h }}</div>
          </div>
          <div v-if="detail.fingerprint">
            <div class="text-xs text-[rgb(125,125,125)]">HTTP 指纹</div>
            <div class="font-mono text-xs" :title="detail.fingerprint">{{ detail.fingerprint }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">UA</div>
            <div class="break-all text-xs">{{ detail.ua || '-' }}</div>
          </div>
          <div class="col-span-2 md:col-span-3">
            <div class="text-xs text-[rgb(125,125,125)]">请求</div>
            <div class="break-all font-mono text-xs">{{ detail.method }} {{ detail.host }}{{ detail.uri }}</div>
          </div>
        </div>

        <div class="flex justify-end">
          <NButton size="small" secondary :loading="replaying" @click="doReplay">重放检测</NButton>
        </div>

        <!-- 请求头 -->
        <div v-if="detailHeaders.length">
          <h4 class="mb-2 text-sm font-semibold">请求头（{{ detailHeaders.length }}）</h4>
          <NDataTable :columns="botHeaderColumns" :data="detailHeaders" :bordered="true" size="small" />
        </div>

        <!-- 请求体 -->
        <div v-if="detail.body">
          <h4 class="mb-2 text-sm font-semibold">请求体（前 8KB）</h4>
          <pre class="max-h-56 overflow-auto whitespace-pre-wrap rounded-lg border border-[rgb(229,229,229)] bg-[rgb(245,245,245)] p-3 font-mono text-xs">{{ detail.body }}</pre>
        </div>
      </div>
    </NModal>

    <!-- 重放检测结果 -->
    <NModal v-model:show="replayOpen" preset="card" title="重放检测结果" class="w-[min(96vw,620px)]" :bordered="false" :style="{ borderRadius: '12px' }">
      <p v-if="!replayHits.length" class="py-6 text-center text-sm text-[rgb(125,125,125)]">未命中任何启用规则（该请求当前规则集不拦截）</p>
      <template v-else>
        <p class="mb-2 text-sm">命中 {{ replayHits.length }} 条规则：</p>
        <NDataTable
          :columns="[
            { title: '规则 ID', key: 'rule_id', width: 100, render: (row: { rule_id: string }) => h('span', { class: 'font-mono text-xs' }, row.rule_id) },
            { title: '描述', key: 'msg' }
          ]"
          :data="replayHits"
          size="small"
          :bordered="false"
        />
      </template>
    </NModal>
  </div>
</template>
