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
  NSelect,
  NSpace,
  NTag,
  NTabs,
  NTabPane
} from 'naive-ui';
import { consumeCcLogs, consumeChallenges, fetchCcLogs, fetchChallenges } from '@/service/api';
import Ja4Identify from '@/components/custom/Ja4Identify.vue';

// —— 通用 ——
function fmtTime(t: string) {
  if (!t) return '-';
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}
function geoText(e: { country?: string; province?: string; city?: string }) {
  return [e.country, e.province, e.city].filter(Boolean).join(' ');
}
function ipCell(clientIp: string, geo: { country?: string; province?: string; city?: string }) {
  return h('div', { class: 'space-y-0.5' }, [
    h('div', { class: 'font-mono text-xs' }, clientIp),
    geo.country
      ? h('div', { class: 'flex items-center gap-1 text-[11px] text-[rgb(125,125,125)]' }, [
          h('span', { class: 'inline-block h-1 w-1 rounded-full bg-[#60a5fa]' }),
          geoText(geo)
        ])
      : null
  ]);
}
function reqCell(host?: string, uri?: string) {
  return h('div', { class: 'max-w-[280px] truncate text-xs' }, [
    h('span', { class: 'text-[rgb(125,125,125)]' }, host || ''),
    h('span', { class: 'font-mono' }, uri || '')
  ]);
}

// ================= CC 触发记录 =================
const ccList = ref<Api.Waf.CcLogItem[]>([]);
const ccTotal = ref(0);
const ccLoading = ref(false);
const ccQuery = reactive({ page: 1, page_size: 20, client_ip: '', rule_name: '' });

async function loadCc() {
  ccLoading.value = true;
  try {
    const res = await fetchCcLogs({
      page: ccQuery.page,
      page_size: ccQuery.page_size,
      ...(ccQuery.client_ip ? { client_ip: ccQuery.client_ip } : {}),
      ...(ccQuery.rule_name ? { rule_name: ccQuery.rule_name } : {})
    });
    ccList.value = res.data?.items ?? [];
    ccTotal.value = res.data?.total ?? 0;
  } finally {
    ccLoading.value = false;
  }
}
async function consumeCc() {
  await consumeCcLogs();
  window.$message?.success('已触发 CC 记录消费');
  await loadCc();
}

const ccColumns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.CcLogItem) => fmtTime(row.time) },
  {
    title: '来源 IP',
    key: 'client_ip',
    minWidth: 150,
    render: (row: Api.Waf.CcLogItem) => ipCell(row.client_ip, row)
  },
  {
    title: '命中规则',
    key: 'rule_name',
    minWidth: 150,
    render: (row: Api.Waf.CcLogItem) => h('span', { class: 'text-xs' }, row.rule_name || '-')
  },
  {
    title: '动作',
    key: 'status',
    width: 90,
    render: (row: Api.Waf.CcLogItem) =>
      row.status >= 400
        ? h(NTag, { size: 'small', type: 'error', bordered: false }, { default: () => '封禁拦截' })
        : h(NTag, { size: 'small', type: 'default', bordered: false }, { default: () => '记录' })
  },
  {
    title: '方法',
    key: 'method',
    width: 76,
    render: (row: Api.Waf.CcLogItem) =>
      h('span', { class: 'rounded border border-[rgb(229,229,229)] px-1.5 py-0.5 font-mono text-[11px]' }, row.method || '-')
  },
  {
    title: '请求',
    key: 'uri',
    minWidth: 220,
    render: (row: Api.Waf.CcLogItem) => reqCell(row.host, row.uri)
  },
  {
    title: '操作',
    key: 'action',
    width: 76,
    render: (row: Api.Waf.CcLogItem) => h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openDetail(row, 'cc') }, { default: () => '详情' })
  }
];

// ================= 人机验证记录 =================
const chList = ref<Api.Waf.ChallengeItem[]>([]);
const chTotal = ref(0);
const chLoading = ref(false);
const chQuery = reactive({ page: 1, page_size: 20, client_ip: '', action: '' });

const actionMeta: Record<string, { label: string; type: 'info' | 'success' | 'error' }> = {
  issue: { label: '下发挑战', type: 'info' },
  pass: { label: '验证通过', type: 'success' },
  fail: { label: '验证失败', type: 'error' }
};

async function loadCh() {
  chLoading.value = true;
  try {
    const res = await fetchChallenges({
      page: chQuery.page,
      page_size: chQuery.page_size,
      ...(chQuery.client_ip ? { client_ip: chQuery.client_ip } : {}),
      ...(chQuery.action ? { action: chQuery.action } : {})
    });
    chList.value = res.data?.items ?? [];
    chTotal.value = res.data?.total ?? 0;
  } finally {
    chLoading.value = false;
  }
}
async function consumeCh() {
  await consumeChallenges();
  window.$message?.success('已触发人机验证记录消费');
  await loadCh();
}

const chColumns = [
  { title: '时间', key: 'time', width: 150, render: (row: Api.Waf.ChallengeItem) => fmtTime(row.time) },
  {
    title: '来源 IP',
    key: 'client_ip',
    minWidth: 150,
    render: (row: Api.Waf.ChallengeItem) => ipCell(row.client_ip, row)
  },
  {
    title: '动作',
    key: 'action',
    width: 100,
    render: (row: Api.Waf.ChallengeItem) =>
      h(NTag, { size: 'small', type: actionMeta[row.action]?.type || 'default', bordered: false }, { default: () => actionMeta[row.action]?.label || row.action })
  },
  {
    title: '命中规则',
    key: 'rule_name',
    minWidth: 150,
    render: (row: Api.Waf.ChallengeItem) => h('span', { class: 'text-xs' }, row.rule_name || '-')
  },
  {
    title: '方法',
    key: 'method',
    width: 76,
    render: (row: Api.Waf.ChallengeItem) =>
      h('span', { class: 'rounded border border-[rgb(229,229,229)] px-1.5 py-0.5 font-mono text-[11px]' }, row.method || '-')
  },
  {
    title: '请求',
    key: 'uri',
    minWidth: 220,
    render: (row: Api.Waf.ChallengeItem) => reqCell(row.host, row.uri)
  },
  {
    title: '操作',
    key: 'action',
    width: 76,
    render: (row: Api.Waf.ChallengeItem) => h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openDetail(row, 'challenge') }, { default: () => '详情' })
  }
];

// ================= 详情弹窗（与攻击事件详情一致） =================
const detailOpen = ref(false);
const detail = ref<Api.Waf.CcLogItem | Api.Waf.ChallengeItem | null>(null);
const detailKind = ref<'cc' | 'challenge'>('cc');

interface HeaderKV {
  name: string;
  value: string;
}
const parsedHeaders = ref<HeaderKV[]>([]);
function parseHeaders(raw?: string): HeaderKV[] {
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? (arr as HeaderKV[]) : [];
  } catch {
    return [];
  }
}

function openDetail(row: Api.Waf.CcLogItem | Api.Waf.ChallengeItem, kind: 'cc' | 'challenge') {
  detail.value = row;
  detailKind.value = kind;
  parsedHeaders.value = parseHeaders(row.headers);
  detailOpen.value = true;
}
function closeDetail() {
  detailOpen.value = false;
  detail.value = null;
}

const headerColumns = [
  { title: '名称', key: 'name', width: 180, render: (row: HeaderKV) => h('span', { class: 'font-mono text-xs' }, row.name) },
  { title: '值', key: 'value', render: (row: HeaderKV) => h('span', { class: 'break-all font-mono text-xs text-[rgb(125,125,125)]' }, row.value) }
];

onMounted(() => {
  loadCc();
  loadCh();
});
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-xl font-semibold">触发记录</h2>
      <p class="text-sm text-[rgb(125,125,125)]">CC 限流与人机验证的触发明细，点击「详情」查看请求头 / 请求体等详细参数</p>
    </div>

    <NTabs type="line" animated>
      <!-- CC 触发记录 -->
      <NTabPane name="cc" tab="CC 触发">
        <NCard :bordered="false" class="card-wrapper">
          <NForm inline label-placement="left" :show-feedback="false">
            <NFormItem label="IP">
              <NInput v-model:value="ccQuery.client_ip" placeholder="如 1.2.3.4" class="w-36" clearable />
            </NFormItem>
            <NFormItem label="规则">
              <NInput v-model:value="ccQuery.rule_name" placeholder="规则名称" class="w-40" clearable />
            </NFormItem>
            <NFormItem>
              <NSpace>
                <NButton type="primary" @click="ccQuery.page = 1; loadCc()">查询</NButton>
                <NButton quaternary @click="Object.assign(ccQuery, { client_ip: '', rule_name: '' }); ccQuery.page = 1; loadCc()">重置</NButton>
              </NSpace>
            </NFormItem>
            <NFormItem style="margin-left: auto">
              <NButton secondary :loading="ccLoading" @click="consumeCc">消费 Redis 队列</NButton>
            </NFormItem>
          </NForm>
          <NDataTable :columns="ccColumns" :data="ccList" :loading="ccLoading" :bordered="false" size="small" />
          <div class="mt-4 flex justify-end">
            <NPagination v-model:page="ccQuery.page" :page-size="ccQuery.page_size" :item-count="ccTotal" @update:page="loadCc" />
          </div>
        </NCard>
      </NTabPane>

      <!-- 人机验证记录 -->
      <NTabPane name="challenge" tab="人机验证">
        <NCard :bordered="false" class="card-wrapper">
          <NForm inline label-placement="left" :show-feedback="false">
            <NFormItem label="IP">
              <NInput v-model:value="chQuery.client_ip" placeholder="如 1.2.3.4" class="w-36" clearable />
            </NFormItem>
            <NFormItem label="动作">
              <NSelect
                v-model:value="chQuery.action"
                :options="[
                  { label: '下发挑战', value: 'issue' },
                  { label: '验证通过', value: 'pass' },
                  { label: '验证失败', value: 'fail' }
                ]"
                clearable
                placeholder="全部"
                class="w-32"
              />
            </NFormItem>
            <NFormItem>
              <NSpace>
                <NButton type="primary" @click="chQuery.page = 1; loadCh()">查询</NButton>
                <NButton quaternary @click="Object.assign(chQuery, { client_ip: '', action: '' }); chQuery.page = 1; loadCh()">重置</NButton>
              </NSpace>
            </NFormItem>
            <NFormItem style="margin-left: auto">
              <NButton secondary :loading="chLoading" @click="consumeCh">消费 Redis 队列</NButton>
            </NFormItem>
          </NForm>
          <NDataTable :columns="chColumns" :data="chList" :loading="chLoading" :bordered="false" size="small" />
          <div class="mt-4 flex justify-end">
            <NPagination v-model:page="chQuery.page" :page-size="chQuery.page_size" :item-count="chTotal" @update:page="loadCh" />
          </div>
        </NCard>
      </NTabPane>
    </NTabs>

    <!-- 触发详情弹窗 -->
    <NModal
      v-model:show="detailOpen"
      preset="card"
      :title="detailKind === 'cc' ? 'CC 触发详情' : '人机验证详情'"
      class="w-[min(96vw,760px)]"
      :bordered="false"
      :style="{ borderRadius: '12px' }"
      @close="closeDetail"
    >
      <div v-if="detail" class="space-y-5">
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
            <div class="text-xs text-[rgb(125,125,125)]">命中规则</div>
            <div>{{ detail.rule_name || '-' }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">方法</div>
            <div>{{ detail.method || '-' }}</div>
          </div>
          <div>
            <div class="text-xs text-[rgb(125,125,125)]">域名</div>
            <div>{{ detail.host || '-' }}</div>
          </div>
          <div v-if="detailKind === 'challenge'">
            <div class="text-xs text-[rgb(125,125,125)]">动作</div>
            <NTag size="small" :type="actionMeta[(detail as Api.Waf.ChallengeItem).action]?.type || 'default'" bordered>
              {{ actionMeta[(detail as Api.Waf.ChallengeItem).action]?.label || (detail as Api.Waf.ChallengeItem).action }}
            </NTag>
          </div>
          <div v-else>
            <div class="text-xs text-[rgb(125,125,125)]">动作</div>
            <NTag size="small" :type="(detail as Api.Waf.CcLogItem).status >= 400 ? 'error' : 'default'" bordered>
              {{ (detail as Api.Waf.CcLogItem).status >= 400 ? '封禁拦截' : '记录' }}
            </NTag>
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
          <div class="col-span-2 md:col-span-3">
            <div class="text-xs text-[rgb(125,125,125)]">请求</div>
            <div class="break-all font-mono text-xs">{{ detail.method }} {{ detail.host }}{{ detail.uri }}</div>
          </div>
        </div>

        <!-- 请求头 -->
        <div>
          <div class="mb-1.5 text-xs font-medium text-[rgb(125,125,125)]">请求头</div>
          <NDataTable
            v-if="parsedHeaders.length > 0"
            :columns="headerColumns"
            :data="parsedHeaders"
            :bordered="false"
            size="small"
            :max-height="220"
          />
          <div v-else class="rounded bg-[rgb(245,245,245)] px-3 py-2 text-xs text-[rgb(125,125,125)]">无请求头记录</div>
        </div>

        <!-- 请求体 -->
        <div>
          <div class="mb-1.5 text-xs font-medium text-[rgb(125,125,125)]">请求体</div>
          <pre v-if="detail.body" class="max-h-52 overflow-auto whitespace-pre-wrap break-all rounded bg-[rgb(245,245,245)] px-3 py-2 font-mono text-xs text-[rgb(60,60,60)]">{{ detail.body }}</pre>
          <div v-else class="rounded bg-[rgb(245,245,245)] px-3 py-2 text-xs text-[rgb(125,125,125)]">无请求体（GET/HEAD 或无内容）</div>
        </div>
      </div>
    </NModal>
  </div>
</template>
