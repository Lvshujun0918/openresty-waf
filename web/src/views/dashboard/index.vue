<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue';
import { NCard, NDataTable, NGrid, NGi, NTag } from 'naive-ui';
import { useEcharts } from '@/hooks/common/echarts';
import type { ECOption } from '@/hooks/common/echarts';
import { fetchDashboardStats, fetchEngines, fetchEvents, fetchTopRegions, fetchTrafficTrend } from '@/service/api';

const mode = ref('active');
const ruleCount = ref(0);
const enabledCount = ref(0);
const recentEvents = ref<Api.Waf.EventItem[]>([]);
const stats = ref<Api.Waf.DashboardStats | null>(null);
const reqTrend = ref<{ date: string; total: number }[]>([]);
const loading = ref(true);
const engineOnline = ref(0);
const engineTotal = ref(0);
const topRegions = ref<{ region: string; count: number }[]>([]);

const groupMeta: Record<string, { label: string; color: string }> = {
  sqli: { label: 'SQL 注入', color: '#ef4444' },
  xss: { label: 'XSS 跨站', color: '#f59e0b' },
  rce: { label: '远程执行', color: '#a855f7' },
  lfi: { label: '文件包含', color: '#f97316' },
  ssrf: { label: 'SSRF', color: '#06b6d4' },
  protocol: { label: '协议异常', color: '#2563eb' },
  leak: { label: '信息泄露', color: '#eab308' },
  scanner: { label: '扫描器', color: '#ec4899' },
  custom: { label: '自定义规则', color: '#64748b' },
  cve: { label: 'CVE 漏洞', color: '#ef4444' },
  hpp: { label: '参数污染', color: '#8b5cf6' },
  api: { label: 'API 安全', color: '#0ea5e9' },
  obfuscation: { label: '编码混淆', color: '#f43f5e' },
  dlp: { label: '敏感数据', color: '#f59e0b' },
  crawler: { label: '爬虫指纹', color: '#22c55e' },
  cc: { label: 'CC 防护', color: '#6366f1' },
  upload: { label: '文件上传', color: '#fb923c' },
  fingerprint: { label: '指纹识别', color: '#94a3b8' },
  trigger: { label: '触发规则', color: '#84cc16' },
  deser: { label: '反序列化', color: '#7c3aed' },
  webshell: { label: 'Webshell', color: '#be185d' }
};

const modeMeta: Record<string, { label: string; type: 'success' | 'warning' | 'default' }> = {
  active: { label: '拦截模式', type: 'success' },
  detect: { label: '监控模式', type: 'warning' },
  off: { label: '放行模式', type: 'default' }
};

// 统计卡（渐变卡片，仿 Soybean demo card-data）
const statCards = computed(() => [
  {
    label: '今日请求',
    value: stats.value?.today.request ?? 0,
    decimals: 0,
    sub: `累计请求 ${formatNum(stats.value?.total.traffic ?? 0)}`,
    color: { start: '#56cdf3', end: '#719de3' },
    icon: 'mdi:web'
  },
  {
    label: '今日拦截',
    value: stats.value?.today.attack ?? 0,
    decimals: 0,
    sub: `累计拦截 ${formatNum(stats.value?.total.events ?? 0)}`,
    color: { start: '#ec4786', end: '#b955a4' },
    icon: 'mdi:shield-alert'
  },
  {
    label: '24H 拦截',
    value: stats.value?.today.intercept_24h ?? 0,
    decimals: 0,
    sub: '近 24 小时命中攻击',
    color: { start: '#fcbc25', end: '#f68057' },
    icon: 'mdi:fire'
  },
  {
    label: '实时 QPS',
    value: Number((stats.value?.qps ?? 0).toFixed(1)),
    decimals: 1,
    sub: '近 60 秒请求均值',
    color: { start: '#865ec0', end: '#5144b4' },
    icon: 'mdi:gauge'
  }
]);

function getGradient(c: { start: string; end: string }) {
  return `linear-gradient(to bottom right, ${c.start}, ${c.end})`;
}

function formatNum(n: number) {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}
function geoText(c?: string, p?: string, ct?: string) {
  return [c, p, ct].filter(Boolean).join(' ');
}
function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

// —— 趋势图 ——
const trendData = computed(() => {
  const atk = stats.value?.attack_trend ?? [];
  const byDate = new Map(reqTrend.value.map(p => [p.date, p.total]));
  return atk.map(p => ({ date: p.date, total: byDate.get(p.date) ?? 0, attack: p.attack }));
});
const trendOption = (): ECOption => ({
  tooltip: { trigger: 'axis' },
  legend: { data: ['请求', '攻击'], top: 0 },
  grid: { left: 40, right: 16, top: 32, bottom: 8 },
  xAxis: { type: 'category', boundaryGap: false, data: trendData.value.map(p => p.date.slice(5)) },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    {
      name: '请求',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#2563eb' },
      areaStyle: { color: 'rgba(37,99,235,0.12)' },
      data: trendData.value.map(p => p.total)
    },
    {
      name: '攻击',
      type: 'line',
      smooth: true,
      showSymbol: false,
      itemStyle: { color: '#ef4444' },
      areaStyle: { color: 'rgba(239,68,68,0.1)' },
      data: trendData.value.map(p => p.attack)
    }
  ]
});
const { domRef: trendRef, updateOptions: updateTrend } = useEcharts(trendOption);

// —— Web 攻击分布（环形图） ——
const donutData = computed(() =>
  (stats.value?.groups ?? []).map(g => ({ name: groupMeta[g.group]?.label || g.group, value: g.count }))
);
const donutOption = (): ECOption => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', right: 0, top: 'center', type: 'scroll' },
  series: [
    {
      name: '攻击分布',
      type: 'pie',
      radius: ['52%', '78%'],
      center: ['38%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
      data: donutData.value.map(item => ({
        ...item,
        itemStyle: {
          color: groupMeta[item.name]?.color ?? Object.values(groupMeta)[donutData.value.findIndex(d => d.name === item.name) % Object.keys(groupMeta).length]?.color
        }
      }))
    }
  ]
});
const { domRef: donutRef, updateOptions: updateDonut } = useEcharts(donutOption);

// —— 归属地分布 ——
const countryData = computed(() => (stats.value?.countries ?? []).map(c => ({ name: c.country, value: c.count })));
const countryOption = (): ECOption => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 24, right: 16, top: 8, bottom: 24 },
  xAxis: { type: 'value', minInterval: 1 },
  yAxis: { type: 'category', data: countryData.value.map(c => c.name).reverse() },
  series: [
    {
      type: 'bar',
      data: countryData.value.map(c => c.value).reverse(),
      itemStyle: { color: '#2563eb', borderRadius: [0, 4, 4, 0] },
      barWidth: 14
    }
  ]
});
const { domRef: countryRef, updateOptions: updateCountry } = useEcharts(countryOption);

// —— 攻击来源 Top 地区（省份） ——
const regionOption = (): ECOption => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 24, right: 16, top: 8, bottom: 24 },
  xAxis: { type: 'value', minInterval: 1 },
  yAxis: { type: 'category', data: topRegions.value.map(r => r.region).reverse() },
  series: [
    {
      type: 'bar',
      data: topRegions.value.map(r => r.count).reverse(),
      itemStyle: { color: '#f59e0b', borderRadius: [0, 4, 4, 0] },
      barWidth: 14
    }
  ]
});
const { domRef: regionRef, updateOptions: updateRegion } = useEcharts(regionOption);

// —— 近期事件表格 ——
const eventColumns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.EventItem) => fmtTime(row.time) },
  {
    title: '来源',
    key: 'client_ip',
    render: (row: Api.Waf.EventItem) => {
      return `${row.client_ip}${row.country ? ` · ${geoText(row.country, row.province, row.city)}` : ''}`;
    }
  },
  { title: '类型', key: 'group', render: (row: Api.Waf.EventItem) => groupMeta[row.group]?.label || row.group },
  { title: '规则', key: 'rule_id' },
  {
    title: '动作',
    key: 'status',
    render: (row: Api.Waf.EventItem) =>
      row.status >= 400
        ? h(NTag, { type: 'error', size: 'small', bordered: false }, { default: () => '拦截' })
        : h(NTag, { type: 'default', size: 'small', bordered: false }, { default: () => '记录' })
  }
];

async function load() {
  loading.value = true;
  try {
    const [st, tr, ev, en, rg] = await Promise.all([
      fetchDashboardStats(14),
      fetchTrafficTrend(14).catch(() => ({ data: { items: [] as { date: string; total: number }[] } })),
      fetchEvents({ page: 1, page_size: 6 }).catch(() => ({ data: { items: [] as Api.Waf.EventItem[] } })),
      fetchEngines().catch(() => ({ data: { engines: [] as Api.Waf.EngineStatus[] } })),
      fetchTopRegions('province', 8).catch(() => ({ data: { items: [] as { region: string; count: number }[] } }))
    ]);
    stats.value = st.data;
    reqTrend.value = tr.data?.items ?? [];
    recentEvents.value = ev.data?.items ?? [];
    ruleCount.value = st.data?.total?.rules ?? 0;
    enabledCount.value = st.data?.total?.rules_enabled ?? 0;
    const engines = en.data?.engines ?? [];
    engineTotal.value = engines.length;
    engineOnline.value = engines.filter(e => e.online).length;
    topRegions.value = rg.data?.items ?? [];
    // 数据更新后需传入最新 option 工厂重新计算（默认 callback 用初始空数据）
    await Promise.all([
      updateTrend(() => trendOption()),
      updateDonut(() => donutOption()),
      updateCountry(() => countryOption()),
      updateRegion(() => regionOption())
    ]);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <!-- 安全态势横幅 -->
    <NCard :bordered="false" class="card-wrapper">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <NTag :type="modeMeta[mode]?.type || 'success'" size="large" round>
            {{ modeMeta[mode]?.label || '拦截模式' }}
          </NTag>
          <div class="text-sm text-[rgb(125,125,125)]">
            命中规则即阻断 · 配置变更 5 秒内热更新生效
          </div>
        </div>
        <div class="flex items-center gap-3">
          <NTag :type="engineTotal > 0 && engineOnline === engineTotal ? 'success' : engineOnline > 0 ? 'warning' : 'error'" size="small" round>
            引擎 {{ engineOnline }}/{{ engineTotal }} 在线
          </NTag>
          <div class="text-sm">规则 {{ ruleCount }} 条 / 启用 {{ enabledCount }} 条</div>
        </div>
      </div>
    </NCard>

    <!-- 统计卡（渐变卡片） -->
    <NGrid :x-gap="16" :y-gap="16" cols="s:1 m:2 l:4" responsive="screen">
      <NGi v-for="card in statCards" :key="card.label">
        <div
          class="px-4 pb-4 pt-2 text-white"
          :style="{ backgroundImage: getGradient(card.color), borderRadius: '8px' }"
        >
          <h3 class="text-sm">{{ card.label }}</h3>
          <div class="flex items-center justify-between pt-3">
            <SvgIcon :icon="card.icon" class="text-3xl opacity-80" />
            <div class="text-right">
              <CountTo :end-value="card.value" :decimals="card.decimals || 0" class="text-2xl font-semibold leading-none" />
              <div class="mt-1 text-[11px] opacity-80">{{ card.sub }}</div>
            </div>
          </div>
        </div>
      </NGi>
    </NGrid>

    <!-- 趋势图 + Web 攻击分布 -->
    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:24 m:14">
        <NCard :bordered="false" class="card-wrapper h-full" title="请求与攻击趋势">
          <template #header-extra>
            <span class="text-xs text-[rgb(125,125,125)]">近 14 天攻击命中 + 全量请求</span>
          </template>
          <div ref="trendRef" class="h-64 w-full" />
        </NCard>
      </NGi>
      <NGi span="24 s:24 m:10">
        <NCard :bordered="false" class="card-wrapper h-full" title="Web 攻击分布">
          <template #header-extra>
            <span class="text-xs text-[rgb(125,125,125)]">攻击类型占比</span>
          </template>
          <div ref="donutRef" class="h-64 w-full" />
        </NCard>
      </NGi>
    </NGrid>

    <!-- 归属地分布 + 攻击来源 Top 10 -->
    <NGrid :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="24 s:24 m:14">
        <NCard :bordered="false" class="card-wrapper h-full" title="攻击来源归属地">
          <template #header-extra>
            <span class="text-xs text-[rgb(125,125,125)]">按国家聚合</span>
          </template>
          <div ref="countryRef" class="h-64 w-full" />
        </NCard>
      </NGi>
      <NGi span="24 s:24 m:10">
        <NCard :bordered="false" class="card-wrapper h-full" title="攻击来源 Top 省份">
          <template #header-extra>
            <span class="text-xs text-[rgb(125,125,125)]">按省份聚合</span>
          </template>
          <div ref="regionRef" class="h-64 w-full" />
        </NCard>
      </NGi>
    </NGrid>

    <!-- 近期攻击事件 -->
    <NCard :bordered="false" class="card-wrapper" title="近期攻击事件">
      <template #header-extra>
        <span class="text-xs text-[rgb(125,125,125)]">最近被检测到的攻击请求</span>
      </template>
      <NDataTable :columns="eventColumns" :data="recentEvents" :loading="loading" :bordered="false" size="small" />
    </NCard>
  </div>
</template>
