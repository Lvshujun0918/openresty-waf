<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPagination,
  NPopconfirm,
  NSelect,
  NSpace,
  NTag
} from 'naive-ui';
import { banEvent, consumeEvents, exemptEvent, exportEventsCsv, fetchEventDetail, fetchEvents, markFalsePositive } from '@/service/api';
import Ja4Identify from '@/components/custom/Ja4Identify.vue';

const groupMeta: Record<string, { label: string; color: string }> = {
  sqli: { label: 'SQL 注入', color: '#ef4444' },
  xss: { label: 'XSS 跨站', color: '#f59e0b' },
  rce: { label: '远程执行', color: '#a855f7' },
  lfi: { label: '文件包含', color: '#f97316' },
  ssrf: { label: 'SSRF', color: '#06b6d4' },
  protocol: { label: '协议异常', color: '#2563eb' },
  leak: { label: '信息泄露', color: '#eab308' },
  scanner: { label: '扫描器', color: '#ec4899' },
  custom: { label: '自定义规则', color: '#64748b' }
};
const groupOptions = Object.keys(groupMeta).map(k => ({ label: groupMeta[k].label, value: k }));
const severityMeta: Record<number, { label: string; type: 'error' | 'warning' | 'info' | 'default' }> = {
  1: { label: '紧急', type: 'error' },
  2: { label: '高危', type: 'error' },
  3: { label: '中危', type: 'warning' },
  4: { label: '低危', type: 'default' }
};

const events = ref<Api.Waf.EventItem[]>([]);
const total = ref(0);
const loading = ref(false);
const query = reactive({ page: 1, page_size: 20, group: '', action: '', client_ip: '', host: '' });

function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}
function geoText(e: Api.Waf.EventItem) {
  return [e.country, e.province, e.city].filter(Boolean).join(' ');
}
function isBlocked(e: Api.Waf.EventItem) {
  return e.status >= 400;
}

async function load() {
  loading.value = true;
  try {
    const res = await fetchEvents({
      page: query.page,
      page_size: query.page_size,
      ...(query.group ? { group: query.group } : {}),
      ...(query.action ? { action: query.action } : {}),
      ...(query.client_ip ? { client_ip: query.client_ip } : {}),
      ...(query.host ? { host: query.host } : {})
    });
    events.value = res.data?.items ?? [];
    total.value = res.data?.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function consume() {
  await consumeEvents();
  window.$message?.success('已触发事件消费');
  await load();
}

// —— 表格列 ——
const columns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.EventItem) => fmtTime(row.time) },
  {
    title: '请求 ID',
    key: 'req_id',
    width: 110,
    render: (row: Api.Waf.EventItem) =>
      h('span', { class: 'font-mono text-xs text-[rgb(125,125,125)]', title: row.req_id || '' }, (row.req_id || '-').slice(-12))
  },
  {
    title: '攻击来源',
    key: 'client_ip',
    minWidth: 150,
    render: (row: Api.Waf.EventItem) =>
      h('div', { class: 'space-y-0.5' }, [
        h('div', { class: 'font-mono text-xs' }, row.client_ip),
        row.country
          ? h(
              'div',
              { class: 'flex items-center gap-1 text-[11px] text-[rgb(125,125,125)]' },
              [h('span', { class: 'inline-block h-1 w-1 rounded-full bg-[#60a5fa]' }), geoText(row)]
            )
          : null
      ])
  },
  {
    title: '攻击类型',
    key: 'group',
    width: 120,
    render: (row: Api.Waf.EventItem) =>
      h(
        NTag,
        { size: 'small', bordered: false, color: { color: `${groupMeta[row.group]?.color || '#6b7280'}20`, textColor: groupMeta[row.group]?.color || '#6b7280' } },
        { default: () => groupMeta[row.group]?.label || row.group }
      )
  },
  {
    title: '命中规则',
    key: 'rule_id',
    minWidth: 180,
    render: (row: Api.Waf.EventItem) =>
      h('div', { class: 'space-y-0.5' }, [
        h('div', { class: 'font-mono text-xs' }, row.rule_id),
        h('div', { class: 'max-w-[180px] truncate text-[11px] text-[rgb(125,125,125)]' }, row.msg)
      ])
  },
  {
    title: '动作',
    key: 'status',
    width: 80,
    render: (row: Api.Waf.EventItem) =>
      isBlocked(row)
        ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '拦截' })
        : h(NTag, { size: 'small', type: 'default', bordered: false }, { default: () => '记录' })
  },
  {
    title: '方法',
    key: 'method',
    width: 76,
    render: (row: Api.Waf.EventItem) =>
      h('span', { class: 'rounded border border-[rgb(229,229,229)] px-1.5 py-0.5 font-mono text-[11px]' }, row.method || '-')
  },
  {
    title: '请求',
    key: 'uri',
    minWidth: 220,
    render: (row: Api.Waf.EventItem) =>
      h('div', { class: 'max-w-[260px] truncate text-xs' }, [
        h('span', { class: 'text-[rgb(125,125,125)]' }, row.host || ''),
        h('span', { class: 'font-mono' }, row.uri)
      ])
  },
  {
    title: '操作',
    key: 'action',
    width: 210,
    render: (row: Api.Waf.EventItem) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openDetail(row.id) }, { default: () => '详情' }),
        h(NButton, { size: 'small', quaternary: true, onClick: () => doExempt(row) }, { default: () => '豁免' }),
        h(
          NPopconfirm,
          {
            positiveText: row.false_positive ? '取消误报' : '标记误报',
            negativeText: '取消',
            onPositiveClick: () => doFlag(row)
          },
          {
            trigger: () =>
              h(
                NButton,
                {
                  size: 'small',
                  quaternary: true,
                  type: row.false_positive ? 'warning' : 'default',
                  onClick: (e: MouseEvent) => e.stopPropagation()
                },
                { default: () => (row.false_positive ? '已误报' : '误报') }
              ),
            default: () =>
              row.false_positive
                ? `取消误报标记？该事件将重新计入规则命中统计`
                : `标记为误报？该事件将从规则命中率统计中排除`
          }
        ),
        h(
          NPopconfirm,
          {
            positiveText: '永久封禁',
            negativeText: '封禁 24 小时',
            onPositiveClick: () => doBan(row, 0),
            onNegativeClick: () => doBan(row, 24)
          },
          {
            trigger: () =>
              h(
                NButton,
                { size: 'small', quaternary: true, type: 'error', disabled: !row.client_ip, onClick: (e: MouseEvent) => e.stopPropagation() },
                { default: () => '封禁' }
              ),
            default: () => `封禁来源 IP ${row.client_ip || ''}？将下发黑名单并热更新生效`
          }
        )
      ])
  }
];

// 标记/取消误报
async function doFlag(row: Api.Waf.EventItem) {
  await markFalsePositive(row.id, !row.false_positive);
  window.$message?.success(row.false_positive ? '已取消误报标记' : '已标记误报');
  await load();
}

// 一键豁免：生成 exempt 触发规则（host + 路径前缀，需到触发规则页发布）
async function doExempt(row: Api.Waf.EventItem) {
  const res = await exemptEvent(row.id);
  window.$message?.success(`已生成豁免规则（ID ${res.data?.rule_id}），请到「触发规则」页发布后生效`);
  await load();
}

// 导出 CSV
async function doExport() {
  const res = await exportEventsCsv({
    ...(query.group ? { group: query.group } : {}),
    ...(query.action ? { action: query.action } : {}),
    ...(query.client_ip ? { client_ip: query.client_ip } : {}),
    ...(query.host ? { host: query.host } : {}),
    limit: 10000
  });
  const url = URL.createObjectURL(res.data as unknown as Blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `waf-events-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// —— 详情弹窗 ——
const detailOpen = ref(false);
const detailLoading = ref(false);

// 一键封禁事件来源 IP（hours<=0 永久）
async function doBan(row: Api.Waf.EventItem, hours: number) {
  const res = await banEvent(row.id, hours);
  window.$message?.success(`已封禁 ${res.data?.ip ?? row.client_ip}（${hours > 0 ? hours + ' 小时' : '永久'}），引擎 5 秒内生效`);
}
const detail = ref<Api.Waf.EventItem | null>(null);

interface RuleHit {
  id: string;
  group: string;
  msg: string;
  severity: number;
}
interface HeaderKV {
  name: string;
  value: string;
}
function parseJson<T>(raw?: string): T[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}
const parsedRules = ref<RuleHit[]>([]);
const parsedHeaders = ref<HeaderKV[]>([]);

async function openDetail(id: number) {
  detailOpen.value = true;
  detailLoading.value = true;
  detail.value = null;
  try {
    const res = await fetchEventDetail(id);
    detail.value = res.data ?? null;
    parsedRules.value = parseJson<RuleHit>(detail.value?.rules);
    parsedHeaders.value = parseJson<HeaderKV>(detail.value?.headers);
  } finally {
    detailLoading.value = false;
  }
}
function closeDetail() {
  detailOpen.value = false;
  detail.value = null;
}

const ruleColumns = [
  { title: '规则 ID', key: 'id', width: 100, render: (row: RuleHit) => h('span', { class: 'font-mono text-xs' }, row.id) },
  {
    title: '类型',
    key: 'group',
    width: 110,
    render: (row: RuleHit) => groupMeta[row.group]?.label || row.group
  },
  {
    title: '级别',
    key: 'severity',
    width: 70,
    render: (row: RuleHit) =>
      h(NTag, { size: 'small', type: severityMeta[row.severity]?.type || 'default', bordered: false }, { default: () => severityMeta[row.severity]?.label || row.severity })
  },
  { title: '描述', key: 'msg' }
];
const headerColumns = [
  { title: '名称', key: 'name', width: 180, render: (row: HeaderKV) => h('span', { class: 'font-mono text-xs' }, row.name) },
  { title: '值', key: 'value', render: (row: HeaderKV) => h('span', { class: 'break-all font-mono text-xs text-[rgb(125,125,125)]' }, row.value) }
];

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">攻击事件</h2>
        <p class="text-sm text-[rgb(125,125,125)]">共 {{ total }} 条 · 攻击日志实时入库</p>
      </div>
      <NButton secondary :loading="loading" @click="consume">消费 Redis 队列</NButton>
      <NButton secondary @click="doExport">导出 CSV</NButton>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NForm inline label-placement="left" :show-feedback="false">
        <NFormItem label="攻击类型">
          <NSelect v-model:value="query.group" :options="groupOptions" clearable placeholder="全部" class="w-32" />
        </NFormItem>
        <NFormItem label="动作">
          <NSelect
            v-model:value="query.action"
            :options="[
              { label: '拦截', value: 'block' },
              { label: '仅记录', value: 'record' }
            ]"
            clearable
            placeholder="全部"
            class="w-28"
          />
        </NFormItem>
        <NFormItem label="IP">
          <NInput v-model:value="query.client_ip" placeholder="如 1.2.3.4" class="w-36" clearable />
        </NFormItem>
        <NFormItem label="域名">
          <NInput v-model:value="query.host" placeholder="如 example.com" class="w-36" clearable />
        </NFormItem>
        <NFormItem>
          <NSpace>
            <NButton type="primary" @click="query.page = 1; load()">查询</NButton>
            <NButton quaternary @click="Object.assign(query, { group: '', action: '', client_ip: '', host: '' }); query.page = 1; load()">重置</NButton>
          </NSpace>
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="events" :loading="loading" :bordered="false" size="small" />
      <div class="mt-4 flex justify-end">
        <NPagination
          v-model:page="query.page"
          :page-size="query.page_size"
          :item-count="total"
          @update:page="load"
        />
      </div>
    </NCard>

    <!-- 事件详情弹窗 -->
    <NModal
      v-model:show="detailOpen"
      preset="card"
      title="攻击事件详情"
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
            <div>{{ geoText(detail) }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">方法</div>
            <div>{{ detail.method || '-' }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">域名</div>
            <div>{{ detail.host || '-' }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">动作</div>
            <NTag size="small" :type="isBlocked(detail) ? 'error' : 'default'" bordered>
              {{ isBlocked(detail) ? '拦截' : '记录' }}
            </NTag>
          </div>
          <div v-if="detail.ja4" class="col-span-2 md:col-span-3">
            <div class="text-xs text-[rgb(125,125,125)]">JA4 指纹</div>
            <div class="flex items-center gap-2">
              <span class="font-mono text-xs" :title="detail.ja4">{{ detail.ja4 }}</span>
              <Ja4Identify :ja4="detail.ja4" />
            </div>
          </div>
          <div class="col-span-2 md:col-span-3">
            <div class="text-xs text-[rgb(125,125,125)]">请求</div>
            <div class="break-all font-mono text-xs">{{ detail.method }} {{ detail.host }}{{ detail.uri }}</div>
          </div>
        </div>

        <!-- 命中规则 -->
        <div>
          <h4 class="mb-2 text-sm font-semibold">命中规则（{{ parsedRules.length }}）</h4>
          <NDataTable v-if="parsedRules.length" :columns="ruleColumns" :data="parsedRules" :bordered="true" size="small" />
          <p v-else class="text-sm text-[rgb(125,125,125)]">无命中规则明细</p>
        </div>

        <!-- 请求头 -->
        <div v-if="parsedHeaders.length">
          <h4 class="mb-2 text-sm font-semibold">请求头（{{ parsedHeaders.length }}）</h4>
          <NDataTable :columns="headerColumns" :data="parsedHeaders" :bordered="true" size="small" />
        </div>

        <!-- 请求体 -->
        <div v-if="detail.body">
          <h4 class="mb-2 text-sm font-semibold">请求体（前 8KB）</h4>
          <pre class="max-h-56 overflow-auto whitespace-pre-wrap rounded-lg border border-[rgb(229,229,229)] bg-[rgb(245,245,245)] p-3 font-mono text-xs">{{ detail.body }}</pre>
        </div>
      </div>
    </NModal>
  </div>
</template>
