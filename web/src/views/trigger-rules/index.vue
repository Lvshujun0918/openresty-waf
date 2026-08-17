<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
  NCheckbox,
  NCheckboxGroup,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NRadio,
  NRadioGroup,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage
} from 'naive-ui';
import {
  createTriggerRule,
  deleteTriggerRule,
  fetchConfig,
  fetchTriggerRules,
  publishTriggerRules,
  saveConfig,
  setTriggerRuleEnabled,
  updateTriggerRule
} from '@/service/api';

const message = useMessage();

const kindMeta: Record<string, { label: string; type: 'primary' | 'success' | 'warning' | 'error'; desc: string }> = {
  challenge: { label: '人机验证', type: 'primary', desc: '命中后需先通过人机验证（JS 挑战 / 验证码）才可访问，验证通道在上方「人机验证全局配置」统一设置' },
  exempt: { label: '豁免检测', type: 'success', desc: '命中后跳过全部规则检测，直接放行（用于可信来源 / 静态资源等）' },
  cc: { label: 'CC 限流', type: 'warning', desc: '命中后参与频率限制，超限自动封禁 IP，频率阈值与封禁时长可在此规则内单独配置' },
  block: { label: '直接拦截', type: 'error', desc: '命中后直接拦截（403），用于对特定爬虫/采集器/来源做分级封禁，detect 模式下仅记录' }
};
const fieldMeta: Record<string, { label: string }> = {
  host: { label: '域名' },
  path: { label: '路径' },
  ua: { label: 'User-Agent' },
  ip: { label: '客户端 IP' },
  method: { label: '请求方法' },
  header: { label: '请求头' },
  args: { label: 'Query 参数' }
};
const opMeta: Record<string, { label: string; short: string }> = {
  equals: { label: '等于', short: '=' },
  prefix: { label: '前缀匹配', short: '前缀' },
  contains: { label: '包含', short: '包含' },
  regex: { label: '正则匹配', short: '正则' },
  cidr: { label: 'IP 段 (CIDR)', short: '属于' },
  in: { label: '枚举 (逗号分隔)', short: '∈' }
};

interface Cond {
  field: string;
  operator: string;
  value: string;
  header: string;
  negate: boolean;
}

// —— 列表 ——
const rules = ref<Api.Waf.TriggerRule[]>([]);
const loading = ref(false);
const kindFilter = ref('');

async function load() {
  loading.value = true;
  try {
    const res = await fetchTriggerRules(kindFilter.value ? { kind: kindFilter.value } : {});
    rules.value = res.data?.items ?? [];
  } finally {
    loading.value = false;
  }
}

async function toggleEnabled(row: Api.Waf.TriggerRule) {
  await setTriggerRuleEnabled(row.id, !row.enabled);
  row.enabled = !row.enabled;
  message.success('已更新');
}

async function remove(row: Api.Waf.TriggerRule) {
  await deleteTriggerRule(row.id);
  message.success('已删除');
  await load();
}

async function doPublish() {
  const res = await publishTriggerRules();
  message.success(`已发布 ${res.data?.version ?? ''}，引擎 5 秒内热更新生效`);
}

function parseConditions(raw?: string): Cond[] {
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr)
      ? arr.map((c: Partial<Cond>) => ({ field: 'host', operator: 'equals', value: '', header: '', negate: false, ...c }))
      : [];
  } catch {
    return [];
  }
}

function condText(c: Cond): string {
  const field = fieldMeta[c.field]?.label || c.field;
  const headerName = c.field === 'header' && c.header ? `[${c.header}]` : '';
  const op = opMeta[c.operator]?.label || c.operator;
  const neg = c.negate ? '非' : '';
  return `${neg}${field}${headerName} ${op} ${c.value || '?'}`;
}

function summary(raw?: string, logic = 'and'): string {
  const conds = parseConditions(raw);
  if (conds.length === 0) return '无条件（所有请求命中）';
  const sep = logic === 'or' ? ' 或 ' : ' 且 ';
  return conds.map(condText).join(sep);
}

const columns = [
  {
    title: '名称',
    key: 'name',
    minWidth: 160,
    render: (row: Api.Waf.TriggerRule) =>
      h('div', { class: 'space-y-0.5' }, [
        h('div', { class: 'text-sm font-medium' }, row.name),
        h('div', { class: 'font-mono text-[11px] text-[rgb(125,125,125)]' }, `#${row.id} · 排序 ${row.sort_order}`)
      ])
  },
  {
    title: '用途',
    key: 'kind',
    width: 110,
    render: (row: Api.Waf.TriggerRule) =>
      h(NTag, { size: 'small', type: kindMeta[row.kind]?.type || 'default', bordered: false }, { default: () => kindMeta[row.kind]?.label || row.kind })
  },
  {
    title: '匹配逻辑',
    key: 'match_logic',
    width: 110,
    render: (row: Api.Waf.TriggerRule) =>
      h(NTag, { size: 'small', type: row.match_logic === 'or' ? 'warning' : 'primary', bordered: false }, { default: () => (row.match_logic === 'or' ? '任一满足 (OR)' : '全部满足 (AND)') })
  },
  {
    title: '触发条件',
    key: 'conditions',
    minWidth: 320,
    render: (row: Api.Waf.TriggerRule) =>
      h(
        'div',
        { class: 'text-xs text-[rgb(80,80,80)]' },
        summary(row.conditions, row.match_logic)
      )
  },
  {
    title: '动作配置',
    key: 'config',
    width: 150,
    render: (row: Api.Waf.TriggerRule) => {
      const cfg = parseConfig(row.config);
      if (row.kind === 'cc') {
        return h('span', { class: 'font-mono text-xs' }, `${cfg.rate || '100/60'} · 封禁${cfg.ban_duration || 300}s`);
      }
      if (row.kind === 'challenge') {
        return h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '全局统一（见上方配置）');
      }
      return h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '-');
    }
  },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: (row: Api.Waf.TriggerRule) => h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 130,
    render: (row: Api.Waf.TriggerRule) =>
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

// —— 编辑弹窗 ——
const editOpen = ref(false);
const saving = ref(false);
const editingId = ref<number | null>(null);
const form = reactive({ name: '', kind: 'challenge', match_logic: 'and', enabled: true, sort_order: 0 });
// 规则级动作配置
const ccConfig = reactive({ rate_count: 100, rate_seconds: 60, ban_duration: 300, dims: [] as string[] });
const conditions = ref<Cond[]>([]);

// —— 人机验证全局配置（所有 challenge 规则共用同一通道）——
const challengeCfg = reactive({
  enabled: true,
  mode: 'basic',
  pow_bits: 20,
  cookie_ttl: 300,
  issue_limit: 20,
  issue_window: 60,
  cookie_secret: '',
  captcha_id: '',
  captcha_key: '',
  brand_title: '',
  brand_company: '',
  brand_contact: ''
});
const chSaving = ref(false);

async function loadChallengeConfig() {
  const res = await fetchConfig();
  const ch = (res.data?.config?.challenge as Record<string, unknown>) ?? {};
  const captcha = (ch.captcha as Record<string, unknown>) ?? {};
  const brand = (ch.brand as Record<string, unknown>) ?? {};
  Object.assign(challengeCfg, {
    enabled: ch.enabled !== false,
    mode: String(ch.mode || 'basic'),
    pow_bits: Number(ch.pow_bits) || 0,
    cookie_ttl: Number(ch.cookie_ttl) || 300,
    issue_limit: Number(ch.issue_limit) || 0,
    issue_window: Number(ch.issue_window) || 60,
    cookie_secret: String(ch.cookie_secret || ''),
    captcha_id: String(captcha.id || ''),
    captcha_key: String(captcha.key || ''),
    brand_title: String(brand.title || ''),
    brand_company: String(brand.company || ''),
    brand_contact: String(brand.contact || '')
  });
}

async function saveChallengeConfig() {
  chSaving.value = true;
  try {
    const res = await fetchConfig();
    const raw = (res.data?.config ?? {}) as Record<string, unknown>;
    const rawCh = (raw.challenge as Record<string, unknown>) ?? {};
    const rawCaptcha = (rawCh.captcha as Record<string, unknown>) ?? {};
    const rawBrand = (rawCh.brand as Record<string, unknown>) ?? {};
    const next = {
      ...raw,
      challenge: {
        ...rawCh,
        enabled: challengeCfg.enabled,
        mode: challengeCfg.mode,
        pow_bits: challengeCfg.pow_bits,
        cookie_ttl: challengeCfg.cookie_ttl,
        issue_limit: challengeCfg.issue_limit,
        issue_window: challengeCfg.issue_window,
        cookie_secret: challengeCfg.cookie_secret,
        captcha: {
          ...rawCaptcha,
          id: challengeCfg.captcha_id,
          key: challengeCfg.captcha_key
        },
        brand: {
          title: challengeCfg.brand_title,
          company: challengeCfg.brand_company,
          contact: challengeCfg.brand_contact
        }
      }
    };
    await saveConfig(next);
    message.success('人机验证全局配置已保存并下发，引擎 5 秒内热更新生效');
  } finally {
    chSaving.value = false;
  }
}

function parseConfig(raw?: string): Record<string, unknown> {
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === 'object' ? obj : {};
  } catch {
    return {};
  }
}

function applyConfig(raw?: string, kind = '') {
  const cfg = parseConfig(raw);
  if (kind === 'cc') {
    const m = String(cfg.rate || '100/60').match(/^(\d+)\/(\d+)$/);
    ccConfig.rate_count = m ? Number(m[1]) : 100;
    ccConfig.rate_seconds = m ? Number(m[2]) : 60;
    ccConfig.ban_duration = Number(cfg.ban_duration) || 300;
    ccConfig.dims = Array.isArray(cfg.dims) ? (cfg.dims as string[]) : [];
  }
}

function buildConfig(kind: string): string {
  if (kind === 'cc') {
    return JSON.stringify({
      rate: `${ccConfig.rate_count}/${ccConfig.rate_seconds}`,
      ban_duration: ccConfig.ban_duration,
      dims: ccConfig.dims
    });
  }
  if (kind === 'challenge') {
    return '{}';
  }
  return '';
}

function resetConfigDefaults(kind: string) {
  if (kind === 'cc') {
    Object.assign(ccConfig, { rate_count: 100, rate_seconds: 60, ban_duration: 300, dims: [] });
  }
}

const fieldOptions = Object.keys(fieldMeta).map(k => ({ label: fieldMeta[k].label, value: k }));
const allOpOptions = Object.keys(opMeta).map(k => ({ label: opMeta[k].label, value: k }));

function opOptions(field: string) {
  if (field === 'ip') return allOpOptions;
  return allOpOptions.filter(o => o.value !== 'cidr');
}

const summaryText = computed(() => {
  const conds = conditions.value.filter(c => c.value !== '' || c.field === 'header');
  if (conds.length === 0) return '无条件（所有请求命中）';
  const sep = form.match_logic === 'or' ? ' 或 ' : ' 且 ';
  return conds.map(condText).join(sep);
});

function emptyCond(): Cond {
  return { field: 'host', operator: 'equals', value: '', header: '', negate: false };
}
function addCondition() {
  conditions.value.push(emptyCond());
}

function openCreate() {
  editingId.value = null;
  Object.assign(form, { name: '', kind: 'challenge', match_logic: 'and', enabled: true, sort_order: 0 });
  resetConfigDefaults(form.kind);
  conditions.value = [emptyCond()];
  editOpen.value = true;
}

function openEdit(row: Api.Waf.TriggerRule) {
  editingId.value = row.id;
  Object.assign(form, {
    name: row.name,
    kind: row.kind,
    match_logic: row.match_logic || 'and',
    enabled: row.enabled,
    sort_order: row.sort_order
  });
  resetConfigDefaults(row.kind);
  applyConfig(row.config, row.kind);
  conditions.value = parseConditions(row.conditions);
  if (conditions.value.length === 0) conditions.value = [emptyCond()];
  editOpen.value = true;
}

function onKindChange(kind: string) {
  resetConfigDefaults(kind);
}

async function save() {
  if (!form.name) {
    message.warning('请填写规则名称');
    return;
  }
  const validConds = conditions.value.filter(c => c.value.trim() !== '' || c.field === 'header');
  if (validConds.length === 0) {
    message.warning('请至少添加一个有效条件');
    return;
  }
  const payload = {
    name: form.name,
    kind: form.kind,
    match_logic: form.match_logic,
    enabled: form.enabled,
    sort_order: form.sort_order,
    conditions: JSON.stringify(validConds),
    config: buildConfig(form.kind)
  };
  saving.value = true;
  try {
    if (editingId.value) {
      await updateTriggerRule(editingId.value, payload);
    } else {
      await createTriggerRule(payload);
    }
    message.success('已保存，请点击「发布到引擎」生效');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

onMounted(load);
onMounted(loadChallengeConfig);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">触发规则</h2>
        <p class="text-sm text-[rgb(125,125,125)]">
          按域名 / User-Agent / 请求头 / IP / 路径等条件筛选请求（支持 AND / OR 组合），命中后执行人机验证、豁免检测或 CC 限流
        </p>
      </div>
      <NSpace>
        <NButton secondary type="warning" @click="doPublish">发布到引擎</NButton>
        <NButton type="primary" @click="openCreate">新建规则</NButton>
      </NSpace>
    </div>

    <NCard :bordered="false" class="card-wrapper" title="人机验证全局配置">
      <template #header-extra>
        <NButton size="small" type="primary" :loading="chSaving" @click="saveChallengeConfig">保存配置</NButton>
      </template>
      <NForm label-placement="left" label-width="120">
        <NFormItem label="启用">
          <NSwitch v-model:value="challengeCfg.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">所有「人机验证」触发规则共用一个验证通道</span>
        </NFormItem>
        <NFormItem label="验证模式">
          <NRadioGroup v-model:value="challengeCfg.mode">
            <NSpace>
              <NRadio value="basic" label="basic（JS 工作量证明）" />
              <NRadio value="geetest" label="geetest（极验）" />
              <NRadio value="gitee" label="gitee（Gitee 验证码）" />
            </NSpace>
          </NRadioGroup>
        </NFormItem>
        <template v-if="challengeCfg.mode !== 'basic'">
          <NFormItem label="Captcha ID">
            <NInput v-model:value="challengeCfg.captcha_id" class="w-80" placeholder="验证码服务商分配的 captcha_id" />
          </NFormItem>
          <NFormItem label="Captcha Key">
            <NInput v-model:value="challengeCfg.captcha_key" class="w-80" type="password" show-password-on="click" placeholder="验证码服务商分配的 captcha_key" />
          </NFormItem>
        </template>
        <NFormItem label="POW 难度(bit)">
          <NInputNumber v-model:value="challengeCfg.pow_bits" :min="0" :max="28" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">basic 模式哈希前导零位数（0 关闭，默认 20）</span>
        </NFormItem>
        <NFormItem label="放行时长(s)">
          <NInputNumber v-model:value="challengeCfg.cookie_ttl" :min="60" class="w-32" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">验证通过后 Cookie 放行时长</span>
        </NFormItem>
        <NFormItem label="签发限频">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">每</span>
            <NInputNumber v-model:value="challengeCfg.issue_window" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">秒最多下发</span>
            <NInputNumber v-model:value="challengeCfg.issue_limit" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">次（超限 444）</span>
          </NSpace>
        </NFormItem>
        <NFormItem label="签名密钥">
          <NInput v-model:value="challengeCfg.cookie_secret" class="w-96" type="password" show-password-on="click" placeholder="cookie_secret（生产环境务必修改）" />
        </NFormItem>
        <NFormItem label="页面标题">
          <NInput v-model:value="challengeCfg.brand_title" class="w-96" placeholder="如：XX 云安全验证（留空用默认）" />
        </NFormItem>
        <NFormItem label="公司/站点名">
          <NInput v-model:value="challengeCfg.brand_company" class="w-96" placeholder="页脚展示，如：XX 科技有限公司" />
        </NFormItem>
        <NFormItem label="联系方式">
          <NInput v-model:value="challengeCfg.brand_contact" class="w-96" placeholder="页脚展示，如：400-xxx-xxxx" />
        </NFormItem>
      </NForm>
    </NCard>

    <NCard :bordered="false" class="card-wrapper">
      <template #header-extra>
        <NSelect
          v-model:value="kindFilter"
          :options="[
            { label: '全部用途', value: '' },
            { label: '人机验证', value: 'challenge' },
            { label: '豁免检测', value: 'exempt' },
            { label: 'CC 限流', value: 'cc' },
            { label: '直接拦截', value: 'block' }
          ]"
          class="w-32"
          @update:value="load"
        />
      </template>
      <NDataTable :columns="columns" :data="rules" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <!-- 条件编辑器 -->
    <NModal
      v-model:show="editOpen"
      preset="card"
      :title="editingId ? '编辑触发规则' : '新建触发规则'"
      class="w-[min(96vw,720px)]"
      :style="{ borderRadius: '12px' }"
    >
      <NForm :model="form" label-placement="left" label-width="90">
        <NFormItem label="名称" required>
          <NInput v-model:value="form.name" placeholder="如：登录接口人机验证" />
        </NFormItem>
        <NFormItem label="用途" required>
          <div class="w-full">
            <NSelect
              v-model:value="form.kind"
              :options="Object.keys(kindMeta).map(k => ({ label: kindMeta[k].label, value: k }))"
              @update:value="onKindChange"
            />
            <div class="mt-2 rounded bg-[rgb(245,245,245)] px-3 py-2 text-xs text-[rgb(80,80,80)]">
              {{ kindMeta[form.kind]?.desc }}
            </div>
          </div>
        </NFormItem>

        <!-- CC 限流规则级配置 -->
        <NFormItem v-if="form.kind === 'cc'" label="频率限制">
          <NSpace align="center" :wrap="true">
            <span class="text-sm text-[rgb(125,125,125)]">每</span>
            <NInputNumber v-model:value="ccConfig.rate_seconds" :min="1" class="w-24" />
            <span class="text-sm text-[rgb(125,125,125)]">秒内最多</span>
            <NInputNumber v-model:value="ccConfig.rate_count" :min="1" class="w-28" />
            <span class="text-sm text-[rgb(125,125,125)]">次</span>
          </NSpace>
        </NFormItem>
        <NFormItem v-if="form.kind === 'cc'" label="封禁时长(s)">
          <NInputNumber v-model:value="ccConfig.ban_duration" :min="1" class="w-32" />
          <span class="ml-2 text-xs text-[rgb(125,125,125)]">超限后封禁该 IP 的秒数</span>
        </NFormItem>
        <NFormItem v-if="form.kind === 'cc'" label="计数维度">
          <NCheckboxGroup v-model:value="ccConfig.dims">
            <NSpace>
              <NCheckbox value="ua">按 UA 独立计数</NCheckbox>
              <NCheckbox value="cookie">无 Cookie 单独计数</NCheckbox>
            </NSpace>
          </NCheckboxGroup>
          <p class="mt-1 text-xs text-[rgb(125,125,125)]">封禁仍为 IP 级；维度用于拆分计数桶，防止单 UA/脚本流量占用共享配额</p>
        </NFormItem>

        <!-- 人机验证规则（验证通道全局统一，无需规则级配置） -->
        <NFormItem label="排序">
          <NInputNumber v-model:value="form.sort_order" :min="0" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="form.enabled" />
        </NFormItem>
        <NFormItem label="匹配逻辑">
          <div class="w-full">
            <NSpace>
              <NTag :type="form.match_logic === 'and' ? 'primary' : 'default'" bordered class="cursor-pointer" @click="form.match_logic = 'and'">
                全部满足 (AND)
              </NTag>
              <NTag :type="form.match_logic === 'or' ? 'warning' : 'default'" bordered class="cursor-pointer" @click="form.match_logic = 'or'">
                任一满足 (OR)
              </NTag>
            </NSpace>
          </div>
        </NFormItem>
        <NFormItem label="触发条件">
          <div class="w-full space-y-2">
            <div
              v-for="(c, i) in conditions"
              :key="i"
              class="rounded-lg border border-[rgb(229,229,229)] bg-[rgb(250,250,250)] p-2"
            >
              <div class="flex flex-wrap items-center gap-2">
                <span
                  v-if="i > 0"
                  class="w-8 text-center text-xs font-semibold"
                  :class="form.match_logic === 'or' ? 'text-[#f59e0b]' : 'text-[#2563eb]'"
                >
                  {{ form.match_logic === 'or' ? '或' : '且' }}
                </span>
                <NSelect v-model:value="c.field" :options="fieldOptions" class="w-32" />
                <NInput
                  v-if="c.field === 'header'"
                  v-model:value="c.header"
                  placeholder="头名，如 User-Agent"
                  class="w-36"
                />
                <NSelect v-model:value="c.operator" :options="opOptions(c.field)" class="w-32" />
                <NInput v-model:value="c.value" placeholder="匹配值" class="w-44" />
                <div class="flex items-center gap-1">
                  <NSwitch v-model:value="c.negate" size="small" />
                  <span class="text-xs text-[rgb(125,125,125)]">取反</span>
                </div>
                <NButton quaternary size="small" type="error" @click="conditions.splice(i, 1)">删除</NButton>
              </div>
            </div>
            <NButton dashed size="small" @click="addCondition">+ 添加条件</NButton>
            <div class="rounded bg-[rgb(245,245,245)] px-3 py-2 text-xs">
              <span class="text-[rgb(125,125,125)]">摘要：</span>
              <span class="text-[rgb(60,60,60)]">{{ summaryText }}</span>
            </div>
          </div>
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editOpen = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="save">保存</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
