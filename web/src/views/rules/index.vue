<script setup lang="ts">
import { fetchRuleStats } from '@/service/api';
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
  exportRules,
  fetchPublishHistory,
  fetchRules,
  importRules,
  publishRules,
  rollbackRules,
  setRuleEnabled,
  testRule,
  updateRule
} from '@/service/api';

const rules = ref<Api.Waf.Rule[]>([]);
const loading = ref(false);
const groupFilter = ref('');
const searchText = ref('');

// ============ 中文术语映射 ============
const groupMeta: Record<string, string> = {
  sqli: 'SQL 注入',
  xss: 'XSS 跨站脚本',
  rce: '命令执行',
  lfi: '文件包含',
  ssrf: '服务端请求伪造',
  protocol: '协议异常',
  leak: '信息泄露',
  scanner: '扫描器',
  response: '响应检测',
  custom: '自定义',
  cve: 'CVE 漏洞攻击',
  hpp: '参数污染',
  api: 'API 安全',
  obfuscation: '编码混淆',
  dlp: '敏感数据泄露',
  crawler: '爬虫指纹',
  cc: 'CC 防护',
  trigger: '触发规则',
  upload: '文件上传',
  fingerprint: '指纹识别'
};
const phaseMeta: Record<string, string> = {
  access: '请求阶段',
  header_filter: '响应头阶段',
  body_filter: '响应体阶段'
};
const operatorMeta: Record<string, string> = {
  REGEX: '正则匹配',
  PM: '词组匹配',
  CONTAINS: '包含子串',
  EQUALS: '完全相等',
  STARTS_WITH: '前缀匹配',
  ENDS_WITH: '后缀匹配',
  CIDR: 'IP 网段',
  EXISTS: '存在即命中',
  LIBINJECTION_SQLI: 'SQL 语义检测',
  LIBINJECTION_XSS: 'XSS 语义检测'
};
const transformMeta: Record<string, string> = {
  url_decode: 'URL 解码',
  url_decode_twice: '多重解码',
  to_lowercase: '转小写',
  remove_comments: '去除注释',
  compress_whitespace: '压缩空白',
  normalize_path: '路径规范化'
};
const varMeta: Record<string, string> = {
  URI: '请求路径',
  REQUEST_URI: '完整请求地址',
  METHOD: '请求方法',
  CLIENT_IP: '客户端 IP',
  USER_AGENT: '浏览器标识',
  URI_ARGS: 'GET 参数',
  POST_ARGS: 'POST 参数',
  BODY: '请求体',
  HEADERS: '请求头（全部）',
  COOKIE: 'Cookie',
  RESPONSE_STATUS: '响应状态码',
  RESPONSE_HEADERS: '响应头（全部）',
  RESPONSE_BODY: '响应体'
};
const actionMeta: Record<string, { label: string; type: 'error' | 'success' | 'info' | 'warning' | 'default' }> = {
  BLOCK: { label: '拦截', type: 'error' },
  DROP: { label: '断开连接', type: 'error' },
  LOG_ONLY: { label: '仅记录', type: 'info' },
  ALLOW: { label: '放行', type: 'success' },
  ACCEPT: { label: '放行', type: 'success' },
  REDIRECT: { label: '跳转', type: 'warning' },
  SCORE: { label: '异常加分', type: 'warning' }
};
const severityMeta: Record<number, { label: string; type: 'error' | 'warning' | 'info' | 'default' }> = {
  1: { label: '紧急', type: 'error' },
  2: { label: '高危', type: 'error' },
  3: { label: '中危', type: 'warning' },
  4: { label: '低危', type: 'default' }
};
const groupOptions = Object.entries(groupMeta).map(([v, l]) => ({ label: l, value: v }));
const phaseOptions = Object.entries(phaseMeta).map(([v, l]) => ({ label: l, value: v }));
const operatorOptions = Object.entries(operatorMeta).map(([v, l]) => ({ label: `${l}（${v}）`, value: v }));
const transformOptions = Object.entries(transformMeta).map(([v, l]) => ({ label: `${l}（${v}）`, value: v }));
const varOptions = Object.entries(varMeta).map(([v, l]) => ({ label: `${l}（${v}）`, value: v }));
const severityOptions = Object.entries(severityMeta).map(([v, m]) => ({ label: `${m.label}（${v} 级）`, value: Number(v) }));
const actionOptions = Object.entries(actionMeta).map(([v, m]) => ({ label: m.label, value: v }));
const operatorPlaceholder: Record<string, string> = {
  REGEX: '正则表达式，如 union\\s+select',
  PM: '多个词组用 | 分隔，如 sqlmap|nikto',
  CONTAINS: '需要包含的子串',
  EQUALS: '需要完全相等的字符串',
  STARTS_WITH: '需要匹配的前缀',
  ENDS_WITH: '需要匹配的后缀',
  CIDR: 'IP 或网段，如 10.0.0.0/8',
  EXISTS: '无需填写（存在即命中）',
  LIBINJECTION_SQLI: '无需填写（词法分析自动识别）',
  LIBINJECTION_XSS: '无需填写（词法分析自动识别）'
};

const filterRules = computed(() => {
  let out = rules.value;
  if (groupFilter.value) out = out.filter(r => r.group === groupFilter.value);
  const kw = searchText.value.trim().toLowerCase();
  if (kw) {
    out = out.filter(r => [r.rule_id, r.name, r.message].some(v => (v || '').toLowerCase().includes(kw)));
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

// —— 规则导入 / 导出 ——
async function doExport() {
  const res = await exportRules();
  const data = res.data;
  if (!Array.isArray(data)) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'waf-rules.json';
  a.click();
  URL.revokeObjectURL(url);
  window.$message?.success(`已导出 ${data.length} 条规则`);
}

const importInputRef = ref<HTMLInputElement | null>(null);

function triggerImport() {
  importInputRef.value?.click();
}

async function onImportFile(ev: Event) {
  const input = ev.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const arr = Array.isArray(parsed) ? parsed : (parsed as { rules?: unknown[] }).rules;
    if (!Array.isArray(arr)) throw new Error('格式错误');
    const res = await importRules(arr);
    window.$message?.success(`导入完成：新增 ${res.data?.imported ?? 0} 条，跳过 ${res.data?.skipped ?? 0} 条（重复/非法规则）`);
    await load();
  } catch {
    window.$message?.error('导入失败：请检查 JSON 格式');
  } finally {
    input.value = '';
  }
}

// —— 编辑表单（引导式 + 高级模式） ——
function safeParse<T>(s: string | undefined | null, fallback: T): T {
  if (!s) return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

const editOpen = ref(false);
const saving = ref(false);
const advancedMode = ref(false);
const form = reactive({
  id: undefined as number | undefined,
  rule_id: '',
  name: '',
  group: 'custom',
  phase: 'access',
  severity: 3,
  enabled: true,
  operator: 'REGEX',
  pattern: '',
  message: '',
  // 引导式字段
  varType: 'URI_ARGS',
  varSpecific: '',
  transformsSelected: [] as string[],
  action: 'BLOCK',
  blockStatus: 403,
  // 高级模式原始 JSON
  varsRaw: '',
  transformsRaw: '',
  actionsRaw: ''
});

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
    message: '',
    varType: 'URI_ARGS',
    varSpecific: '',
    transformsSelected: [],
    action: 'BLOCK',
    blockStatus: 403,
    varsRaw: '',
    transformsRaw: '',
    actionsRaw: ''
  });
  advancedMode.value = false;
  editOpen.value = true;
}

function openEdit(row: Api.Waf.Rule) {
  const varsArr = safeParse<any[]>(row.vars, []);
  const actObj = safeParse<Record<string, any>>(row.actions, {});
  const trArr = safeParse<string[]>(row.transforms, []);
  // 仅单检测位置且无 chain 等高级动作时可引导式编辑，否则进入高级模式
  if (Array.isArray(varsArr) && varsArr.length === 1 && !actObj.chain) {
    advancedMode.value = false;
    const v0 = varsArr[0] || {};
    Object.assign(form, {
      id: row.id,
      rule_id: row.rule_id,
      name: row.name,
      group: row.group,
      phase: row.phase,
      severity: row.severity,
      enabled: row.enabled,
      operator: row.operator,
      pattern: row.pattern,
      message: row.message,
      varType: v0.type || 'URI_ARGS',
      varSpecific: v0.specific || '',
      transformsSelected: trArr.filter(t => transformMeta[t]),
      action: actObj.disrupt || 'BLOCK',
      blockStatus: actObj.status || 403
    });
  } else {
    advancedMode.value = true;
    Object.assign(form, {
      id: row.id,
      rule_id: row.rule_id,
      name: row.name,
      group: row.group,
      phase: row.phase,
      severity: row.severity,
      enabled: row.enabled,
      operator: row.operator,
      pattern: row.pattern,
      message: row.message,
      varsRaw: row.vars || '',
      transformsRaw: row.transforms || '',
      actionsRaw: row.actions || ''
    });
  }
  editOpen.value = true;
}

// 切到高级模式时，把引导式字段同步成等价 JSON，便于继续微调
function onToggleAdvanced(on: boolean) {
  if (on) {
    form.varsRaw = JSON.stringify([
      { type: form.varType, ...(form.varSpecific ? { specific: form.varSpecific } : {}) }
    ]);
    form.transformsRaw = JSON.stringify(form.transformsSelected);
    const act: Record<string, any> = { disrupt: form.action };
    if (form.action === 'BLOCK') act.status = form.blockStatus || 403;
    if (form.message) act.msg = form.message;
    form.actionsRaw = JSON.stringify(act);
  }
}

function buildPayload(): Partial<Api.Waf.Rule> {
  const base = {
    rule_id: form.rule_id,
    name: form.name,
    group: form.group,
    phase: form.phase,
    severity: form.severity,
    enabled: form.enabled,
    operator: form.operator,
    pattern: form.pattern,
    message: form.message
  };
  if (advancedMode.value) {
    return { ...base, vars: form.varsRaw, transforms: form.transformsRaw, actions: form.actionsRaw };
  }
  const vars = [{ type: form.varType, ...(form.varSpecific ? { specific: form.varSpecific } : {}) }];
  const act: Record<string, any> = { disrupt: form.action };
  if (form.action === 'BLOCK') act.status = form.blockStatus || 403;
  if (form.message) act.msg = form.message;
  const statusMap: Record<string, number> = { BLOCK: form.blockStatus || 403, DROP: 444, LOG_ONLY: 200, ALLOW: 200, ACCEPT: 200, REDIRECT: 302, SCORE: 403 };
  return {
    ...base,
    vars: JSON.stringify(vars),
    transforms: JSON.stringify(form.transformsSelected),
    actions: JSON.stringify(act),
    status: statusMap[form.action] ?? 403
  };
}

async function save() {
  saving.value = true;
  try {
    const payload = buildPayload();
    if (form.id) {
      await updateRule(form.id, payload);
    } else {
      await createRule(payload);
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
  if (!testForm.ruleId.trim()) {
    window.$message?.warning('请先填写要测试的规则编号');
    return;
  }
  testing.value = true;
  testResult.value = null;
  try {
    const res = await testRule({
      rule_id: testForm.ruleId,
      request: {
        method: testForm.method,
        uri: testForm.uri,
        body: testForm.body,
        content_type: testForm.content_type
      }
    });
    testResult.value = res.data ?? null;
  } finally {
    testing.value = false;
  }
}

// ============ 表格列 ============
function renderAction(row: Api.Waf.Rule) {
  const a = safeParse<Record<string, any>>(row.actions, {});
  const m = actionMeta[a.disrupt];
  const label = m ? m.label : a.chain ? '链式' : a.disrupt || '未知';
  const tags = [
    h(
      NTag,
      { size: 'small', type: (m?.type || 'default') as 'default', bordered: false },
      { default: () => h('span', { title: row.actions || '' }, label) }
    )
  ];
  if (a.chain) {
    tags.push(h(NTag, { size: 'small', type: 'default', bordered: false }, { default: () => '链式' }));
  }
  return h(NSpace, { size: 2, wrap: false }, tags);
}

const columns = [
  { title: '规则编号', key: 'rule_id', width: 100, render: (row: Api.Waf.Rule) => h('span', { class: 'font-mono text-xs' }, row.rule_id) },
  { title: '名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  {
    title: '攻击类型',
    key: 'group',
    width: 120,
    render: (row: Api.Waf.Rule) =>
      h(NTag, { size: 'small', bordered: false }, { default: () => groupMeta[row.group] || row.group })
  },
  { title: '检测阶段', key: 'phase', width: 100, render: (row: Api.Waf.Rule) => phaseMeta[row.phase] || row.phase },
  {
    title: '危险级别',
    key: 'severity',
    width: 80,
    render: (row: Api.Waf.Rule) =>
      h(NTag, { size: 'small', type: severityMeta[row.severity]?.type || 'default', bordered: false }, { default: () => severityMeta[row.severity]?.label || row.severity })
  },
  { title: '匹配方式', key: 'operator', width: 100, render: (row: Api.Waf.Rule) => operatorMeta[row.operator] || row.operator },
  { title: '处置', key: 'actions', width: 110, render: renderAction },
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

type RuleStat = { rule_id: string; hits: number; blocks: number; fps: number; fp_rate?: number };
const highFpRules = ref<RuleStat[]>([]);

async function loadRuleStats() {
  const res = await fetchRuleStats('', 20).catch(() => ({ data: { items: [] as RuleStat[] } }));
  const items = (res.data?.items ?? []).filter(x => (x.fp_rate ?? 0) >= 20 && x.hits >= 3);
  highFpRules.value = items;
}

onMounted(() => {
  load();
  loadRuleStats();
});
</script>

<template>
  <div class="space-y-4">
    <NAlert v-if="highFpRules.length" type="warning" :bordered="false" class="card-wrapper" title="高误报规则提醒">
      以下规则误报率 ≥20%（命中 ≥3 次）：{{ highFpRules.map(r => r.rule_id + '（' + (r.fp_rate ?? 0).toFixed(0) + '%）').join('、') }} —— 建议复查规则或对相关路径配置豁免
    </NAlert>
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">规则管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">共 {{ filterRules.length }} 条 · 发布后引擎 5 秒内热更新生效</p>
      </div>
      <NSpace>
        <NButton secondary @click="doExport">导出</NButton>
        <NButton secondary @click="triggerImport">导入</NButton>
        <NButton secondary @click="historyOpen = true; loadHistory()">发布历史</NButton>
        <NButton secondary type="warning" @click="doPublish">发布到引擎</NButton>
        <NButton type="primary" @click="openCreate">新建规则</NButton>
        <input ref="importInputRef" type="file" accept=".json,application/json" class="hidden" @change="onImportFile" />
      </NSpace>
    </div>

    <!-- 规则测试（置顶） -->
    <NCard :bordered="false" class="card-wrapper" title="规则在线测试">
      <template #header-extra>
        <span class="text-xs text-[rgb(125,125,125)]">用模拟请求验证规则是否命中，确认无误再发布</span>
      </template>
      <NForm inline label-placement="left" :show-feedback="false">
        <NFormItem label="规则编号">
          <NInput v-model:value="testForm.ruleId" placeholder="如 942100" class="w-32" />
        </NFormItem>
        <NFormItem label="请求方法">
          <NSelect v-model:value="testForm.method" :options="['GET', 'POST', 'PUT'].map(v => ({ label: v, value: v }))" class="w-24" />
        </NFormItem>
        <NFormItem label="请求地址">
          <NInput v-model:value="testForm.uri" placeholder="/path?a=1" class="w-56" />
        </NFormItem>
        <NFormItem label="内容类型">
          <NSelect
            v-model:value="testForm.content_type"
            :options="[
              { label: '表单', value: 'application/x-www-form-urlencoded' },
              { label: 'JSON', value: 'application/json' }
            ]"
            class="w-28"
          />
        </NFormItem>
        <NFormItem label="请求体">
          <NInput v-model:value="testForm.body" placeholder="POST 请求体（可选）" class="w-56" />
        </NFormItem>
        <NFormItem>
          <NButton type="primary" :loading="testing" @click="doTest">测试</NButton>
        </NFormItem>
      </NForm>
      <div v-if="testResult" class="mt-3">
        <NTag :type="testResult.matched ? 'error' : 'success'" size="large">
          {{ testResult.matched ? '命中（将触发拦截）' : '未命中' }}
        </NTag>
        <p v-if="testResult.note" class="mt-2 text-xs text-[rgb(125,125,125)]">{{ testResult.note }}</p>
      </div>
    </NCard>

    <!-- 规则列表 -->
    <NCard :bordered="false" class="card-wrapper">
      <template #header-extra>
        <NSpace>
          <NInput v-model:value="searchText" placeholder="搜索编号/名称/说明" clearable class="w-48" />
          <NSelect v-model:value="groupFilter" :options="groupOptions" clearable placeholder="按攻击类型筛选" class="w-40" />
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="filterRules" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <!-- 编辑表单 -->
    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑规则' : '新建规则'" class="w-[min(96vw,680px)]">
      <NForm label-placement="left" label-width="96">
        <div class="mb-2 flex items-center justify-between rounded bg-[#f5f7fa] px-3 py-2">
          <span class="text-xs text-[rgb(125,125,125)]">高级模式（直接编辑原始 JSON，适用于链式等多检测位置规则）</span>
          <NSwitch :value="advancedMode" size="small" @update:value="onToggleAdvanced" />
        </div>

        <NFormItem label="规则编号" required>
          <NInput v-model:value="form.rule_id" placeholder="如 1001（自定义规则建议 9000+，避免与内置规则冲突）" />
        </NFormItem>
        <NFormItem label="规则名称" required>
          <NInput v-model:value="form.name" placeholder="如 拦截上传可疑文件" />
        </NFormItem>
        <NFormItem label="攻击类型" required>
          <NSelect v-model:value="form.group" :options="groupOptions" />
        </NFormItem>
        <NFormItem label="检测阶段">
          <NSelect v-model:value="form.phase" :options="phaseOptions" />
        </NFormItem>
        <NFormItem label="匹配方式" required>
          <NSelect v-model:value="form.operator" :options="operatorOptions" />
        </NFormItem>
        <NFormItem v-if="form.operator !== 'EXISTS' && form.operator !== 'LIBINJECTION_SQLI' && form.operator !== 'LIBINJECTION_XSS'" label="匹配内容" required>
          <NInput v-model:value="form.pattern" type="textarea" :rows="2" :placeholder="operatorPlaceholder[form.operator] || '匹配内容'" />
        </NFormItem>

        <template v-if="!advancedMode">
          <NFormItem label="检测位置">
            <NSelect v-model:value="form.varType" :options="varOptions" />
          </NFormItem>
          <NFormItem label="指定字段">
            <NInput v-model:value="form.varSpecific" placeholder="可选，如 id 或 user-agent（留空检测该位置的全部内容）" />
          </NFormItem>
          <NFormItem label="预处理">
            <NSelect v-model:value="form.transformsSelected" :options="transformOptions" multiple clearable placeholder="对内容先做哪些归一化处理（可多选）" />
          </NFormItem>
          <NFormItem label="处置动作" required>
            <NSelect v-model:value="form.action" :options="actionOptions" />
          </NFormItem>
          <NFormItem v-if="form.action === 'BLOCK'" label="拦截状态码">
            <NInputNumber v-model:value="form.blockStatus" :min="200" :max="599" class="w-32" />
            <span class="ml-2 text-xs text-[rgb(125,125,125)]">默认 403；填 444 表示直接断开连接</span>
          </NFormItem>
        </template>

        <template v-else>
          <NFormItem label="检测位置">
            <NInput v-model:value="form.varsRaw" type="textarea" :rows="2" class="font-mono" placeholder="[{&quot;type&quot;:&quot;URI_ARGS&quot;,&quot;specific&quot;:&quot;id&quot;}]" />
          </NFormItem>
          <NFormItem label="预处理">
            <NInput v-model:value="form.transformsRaw" class="font-mono" placeholder="[&quot;url_decode&quot;,&quot;to_lowercase&quot;]" />
          </NFormItem>
          <NFormItem label="动作">
            <NInput v-model:value="form.actionsRaw" type="textarea" :rows="2" class="font-mono" placeholder="{&quot;disrupt&quot;:&quot;BLOCK&quot;,&quot;status&quot;:403,&quot;msg&quot;:&quot;...&quot;}" />
          </NFormItem>
        </template>

        <NFormItem label="说明">
          <NInput v-model:value="form.message" placeholder="命中后展示在攻击事件中的说明（可选）" />
        </NFormItem>
        <NFormItem label="危险级别">
          <NSelect v-model:value="form.severity" :options="severityOptions" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="form.enabled" />
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
  </div>
</template>
