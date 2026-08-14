<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  NInputNumber
} from 'naive-ui';
import {
  createRule,
  deleteRule,
  fetchPublishHistory,
  fetchRules,
  fetchSites,
  publishRules,
  rollbackRules,
  setRuleEnabled,
  testRule,
  updateRule
} from '@/service/api';

const rules = ref<Api.Waf.Rule[]>([]);
const loading = ref(false);
const groupFilter = ref('');
const siteFilter = ref<number | null>(null);
const sites = ref<Api.Waf.Site[]>([]);
const groupOptions = ['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'protocol', 'leak', 'scanner', 'custom'].map(g => ({
  label: g,
  value: g
}));
const siteOptions = computed(() => [
  { label: '全局规则', value: 0 },
  ...sites.value.map(s => ({ label: `${s.name}（${s.domain}）`, value: s.id }))
]);
const siteNameMap = computed(() => Object.fromEntries(sites.value.map(s => [s.id, s.name])));
const siteFilterOptions = computed(() => [
  { label: '全局规则', value: 0 },
  ...sites.value.map(s => ({ label: s.name, value: s.id }))
]);
const severityMeta: Record<number, { label: string; type: 'error' | 'warning' | 'info' | 'default' }> = {
  1: { label: '紧急', type: 'error' },
  2: { label: '高危', type: 'error' },
  3: { label: '中危', type: 'warning' },
  4: { label: '低危', type: 'default' }
};

const filterRules = computed(() => {
  let out = rules.value;
  if (groupFilter.value) out = out.filter(r => r.group === groupFilter.value);
  if (siteFilter.value !== null) {
    const sid = siteFilter.value;
    out = out.filter(r => (r.site_id || 0) === sid);
  }
  return out;
});

async function load() {
  loading.value = true;
  try {
    const res = await fetchRules();
    rules.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function loadSites() {
  const res = await fetchSites();
  sites.value = res.data ?? [];
}

async function toggleEnabled(row: Api.Waf.Rule) {
  await setRuleEnabled(row.id, !row.enabled);
  row.enabled = !row.enabled;
  window.$message?.success('已更新');
}

async function remove(row: Api.Waf.Rule) {
  await deleteRule(row.id);
  window.$message?.success('已删除');
  await load();
}

async function doPublish() {
  const res = await publishRules();
  window.$message?.success('规则已发布，引擎 5 秒内热更新生效');
}

// —— 发布历史与回滚 ——
const historyOpen = ref(false);
const historyLoading = ref(false);
const rollingBackId = ref<number | null>(null);
const history = ref<Api.Waf.PublishHistory[]>([]);

function formatTime(t: string) {
  return t.replace('T', ' ').replace(/\.\d+/, '').replace(/Z$/, '').replace(/[+-]\d{2}:\d{2}$/, '');
}

const historyColumns = [
  { title: '版本', key: 'version', width: 100, render: (row: Api.Waf.PublishHistory) => h('span', { class: 'font-mono text-xs' }, `#${row.version}`) },
  { title: '规则数', key: 'rule_count', width: 80 },
  { title: '发布时间', key: 'created_at', render: (row: Api.Waf.PublishHistory) => h('span', { class: 'text-xs' }, formatTime(row.created_at)) },
  {
    title: '操作',
    key: 'action',
    width: 90,
    render: (row: Api.Waf.PublishHistory) =>
      h(
        NPopconfirm,
        { onPositiveClick: () => doRollback(row) },
        {
          trigger: () =>
            h(NButton, { size: 'small', quaternary: true, type: 'warning', loading: rollingBackId.value === row.id }, { default: () => '回滚' }),
          default: () => `回滚到版本 #${row.version}？将重新下发该版本的规则集`
        }
      )
  }
];

async function loadHistory() {
  historyLoading.value = true;
  try {
    const res = await fetchPublishHistory();
    history.value = res.data ?? [];
  } finally {
    historyLoading.value = false;
  }
}

async function doRollback(row: Api.Waf.PublishHistory) {
  rollingBackId.value = row.id;
  try {
    await rollbackRules(row.id);
    window.$message?.success(`已回滚到版本 #${row.version}，引擎 5 秒内热更新生效`);
    await loadHistory();
    await load();
  } finally {
    rollingBackId.value = null;
  }
}

// —— 编辑表单 ——
const editOpen = ref(false);
const saving = ref(false);
const formRef = ref();
const form = reactive<Partial<Api.Waf.Rule>>({
  rule_id: '',
  name: '',
  group: 'custom',
  phase: 'access',
  severity: 3,
  enabled: true,
  operator: 'REGEX',
  pattern: '',
  transforms: '',
  vars: '',
  actions: 'BLOCK',
  status: 0,
  message: ''
});
const rulesForForm = [
  { key: 'rule_id', label: '规则 ID', required: true },
  { key: 'name', label: '规则名', required: true },
  { key: 'group', label: '类型', type: 'select' },
  { key: 'phase', label: '阶段', type: 'select', options: [{ label: 'access', value: 'access' }, { label: 'header_filter', value: 'header_filter' }] },
  { key: 'severity', label: '级别', type: 'number' },
  { key: 'enabled', label: '启用', type: 'switch' },
  { key: 'operator', label: '运算符', type: 'select', options: ['REGEX', 'PM', 'EQUALS', 'CONTAINS', 'CIDR'].map(v => ({ label: v, value: v })) },
  { key: 'pattern', label: '匹配模式', type: 'textarea' },
  { key: 'transforms', label: '变换链', placeholder: '如 url_decode,lowercase' },
  { key: 'vars', label: '变量', placeholder: '如 URI_ARGS|id' },
  { key: 'actions', label: '动作', type: 'select', options: ['BLOCK', 'LOG_ONLY', 'ALLOW', 'SCORE'].map(v => ({ label: v, value: v })) },
  { key: 'message', label: '描述', type: 'textarea' }
];

function openCreate() {
  Object.assign(form, {
    id: undefined,
    rule_id: '',
    name: '',
    group: 'custom',
    phase: 'access',
    severity: 3,
    enabled: true,
    operator: 'REGEX',
    pattern: '',
    transforms: '',
    vars: '',
    actions: 'BLOCK',
    status: 0,
    message: '',
    site_id: 0
  });
  editOpen.value = true;
}

function openEdit(row: Api.Waf.Rule) {
  Object.assign(form, row);
  editOpen.value = true;
}

async function save() {
  saving.value = true;
  try {
    if (form.id) {
      await updateRule(form.id, form);
    } else {
      await createRule(form);
    }
    window.$message?.success('已保存');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

// —— 规则测试 ——
const testForm = reactive({ ruleId: '', uri: '/', method: 'GET', body: '', content_type: 'application/x-www-form-urlencoded' });
const testResult = ref<{ matched: boolean; note?: string } | null>(null);
const testing = ref(false);

async function doTest() {
  testing.value = true;
  testResult.value = null;
  try {
    const res = await testRule({ ...testForm });
    testResult.value = res.data ?? null;
  } finally {
    testing.value = false;
  }
}

const columns = [
  { title: '规则 ID', key: 'rule_id', width: 100, render: (row: Api.Waf.Rule) => h('span', { class: 'font-mono text-xs' }, row.rule_id) },
  { title: '名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  {
    title: '站点',
    key: 'site_id',
    width: 110,
    render: (row: Api.Waf.Rule) =>
      (row.site_id || 0) === 0
        ? h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '全局')
        : h(NTag, { size: 'small', bordered: false }, { default: () => siteNameMap.value[row.site_id] || row.site_id })
  },
  { title: '类型', key: 'group', width: 100, render: (row: Api.Waf.Rule) => h(NTag, { size: 'small', bordered: false }, { default: () => row.group }) },
  { title: '阶段', key: 'phase', width: 110 },
  {
    title: '级别',
    key: 'severity',
    width: 70,
    render: (row: Api.Waf.Rule) =>
      h(NTag, { size: 'small', type: severityMeta[row.severity]?.type || 'default', bordered: false }, { default: () => severityMeta[row.severity]?.label || row.severity })
  },
  { title: '运算符', key: 'operator', width: 90 },
  { title: '动作', key: 'actions', width: 90, render: (row: Api.Waf.Rule) => h('span', { class: 'font-mono text-xs' }, row.actions) },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: (row: Api.Waf.Rule) => h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 140,
    render: (row: Api.Waf.Rule) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => remove(row) },
          {
            trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }),
            default: () => '确认删除该规则？'
          }
        )
      ])
  }
];

onMounted(() => {
  load();
  loadSites();
});
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">规则管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">共 {{ filterRules.length }} 条 · 发布后引擎 5 秒内热更新生效</p>
      </div>
      <NSpace>
        <NButton secondary @click="historyOpen = true; loadHistory()">发布历史</NButton>
        <NButton secondary type="warning" @click="doPublish">发布到引擎</NButton>
        <NButton type="primary" @click="openCreate">新建规则</NButton>
      </NSpace>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <template #header-extra>
        <NSpace>
          <NSelect v-model:value="siteFilter" :options="siteFilterOptions" clearable placeholder="按站点筛选" class="w-36" />
          <NSelect v-model:value="groupFilter" :options="groupOptions" clearable placeholder="按类型筛选" class="w-32" />
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="filterRules" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <!-- 编辑表单 -->
    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑规则' : '新建规则'" class="w-[min(96vw,640px)]">
      <NForm ref="formRef" :model="form" label-placement="left" label-width="90">
        <NFormItem v-for="f in rulesForForm" :key="f.key" :label="f.label" :required="f.required">
          <NInput v-if="!f.type || f.type === 'text'" v-model:value="(form as any)[f.key]" />
          <NInput v-else-if="f.type === 'textarea'" v-model:value="(form as any)[f.key]" type="textarea" :rows="2" />
          <NSelect v-else-if="f.type === 'select'" v-model:value="(form as any)[f.key]" :options="f.options || groupOptions" />
          <NSwitch v-else-if="f.type === 'switch'" v-model:value="(form as any)[f.key]" />
          <NInputNumber v-else-if="f.type === 'number'" v-model:value="(form as any)[f.key]" :min="0" :max="4" />
        </NFormItem>
        <NFormItem label="归属站点">
          <NSelect v-model:value="form.site_id" :options="siteOptions" />
          <p class="mt-1 text-xs text-[rgb(125,125,125)]">全局规则对所有域名生效；站点规则仅对对应域名生效，修改后需发布</p>
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editOpen = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="save">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 发布历史 -->
    <NModal v-model:show="historyOpen" preset="card" title="发布历史与回滚" class="w-[min(96vw,640px)]">
      <p class="mb-3 text-xs text-[rgb(125,125,125)]">每次发布保存完整规则集快照，回滚后引擎按新版本号热更新（版本单调递增，可在发布历史中持续追踪）</p>
      <NDataTable :columns="historyColumns" :data="history" :loading="historyLoading" :bordered="false" size="small" />
    </NModal>

    <!-- 规则测试 -->
    <NCard :bordered="false" class="card-wrapper" title="规则测试">
      <template #header-extra>
        <span class="text-xs text-[rgb(125,125,125)]">本地匹配器验证规则是否命中</span>
      </template>
      <NSpace wrap>
        <NInput v-model:value="testForm.ruleId" placeholder="规则 ID，如 942100" class="w-40" />
        <NSelect v-model:value="testForm.method" :options="['GET', 'POST', 'PUT'].map(v => ({ label: v, value: v }))" class="w-24" />
        <NInput v-model:value="testForm.uri" placeholder="/path?a=1" class="w-56" />
        <NInput v-model:value="testForm.body" placeholder="请求体（POST）" class="w-56" />
        <NButton type="primary" :loading="testing" @click="doTest">测试</NButton>
      </NSpace>
      <div v-if="testResult" class="mt-3">
        <NTag :type="testResult.matched ? 'error' : 'success'" size="large">
          {{ testResult.matched ? '命中（将触发拦截）' : '未命中' }}
        </NTag>
        <p v-if="testResult.note" class="mt-2 text-xs text-[rgb(125,125,125)]">{{ testResult.note }}</p>
      </div>
    </NCard>
  </div>
</template>
