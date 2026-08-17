<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import {
  NButton,
  NCard,
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
  NTabPane,
  NTabs,
  NTag,
  NAlert
} from 'naive-ui';
import { createIpListSub, deleteIpListSub, fetchIpListSubs, setIpListSubEnabled, syncIpListSub, updateIpListSub } from '@/service/api';

// 订阅目标 tab
type Target = 'ip' | 'fingerprint' | 'bot_profile' | 'ja4_profile';
const activeTarget = ref<Target>('ip');

const subs = ref<Api.Waf.IpListSub[]>([]);
const loading = ref(false);

const targetMeta: Record<Target, { label: string; hint: string; placeholder: string }> = {
  ip: {
    label: '恶意/信任 IP 库',
    hint: '订阅远程 IP 情报（每行一个 IP/CIDR），同步后合并进黑/白名单下发引擎',
    placeholder: 'https://example.com/ips.txt（每行一个 IP/CIDR，# 注释）'
  },
  fingerprint: {
    label: '恶意指纹库',
    hint: '订阅远程恶意指纹情报（JSON 数组或每行 名称|指纹值[|exact|regex]），同步后进入恶意指纹库并下发拦截',
    placeholder: 'JSON 数组 [{"name":"..","value":"..","match":"exact"}] 或每行 名称|值|match'
  },
  bot_profile: {
    label: '爬虫画像库',
    hint: '订阅远程爬虫画像（JSON 数组），同步后进入爬虫画像库并下发引擎识别',
    placeholder: 'JSON 数组 [{"name":"Googlebot","ua":"Googlebot","ips":["66.249.64.0/19"],"engine":true}]'
  },
  ja4_profile: {
    label: 'JA4 客户端库',
    hint: '订阅远程 JA4 客户端指纹（CSV：每行 名称,ja4[,分类]），同步后进入 JA4 客户端库；malware 类自动联动恶意指纹库拦截',
    placeholder: 'CSV 每行 名称,ja4[,malware|browser|tool]，如 Sliver Agent,t13d190900_9dc949149365_97f8aa674fd9,malware'
  }
};

const filtered = computed(() => subs.value.filter(s => s.target === activeTarget.value));

async function load() {
  loading.value = true;
  try {
    const res = await fetchIpListSubs();
    subs.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function toggleEnabled(row: Api.Waf.IpListSub) {
  await setIpListSubEnabled(row.id, !row.enabled);
  row.enabled = !row.enabled;
  window.$message?.success('已更新');
}

async function remove(row: Api.Waf.IpListSub) {
  await deleteIpListSub(row.id);
  window.$message?.success('已删除');
  await load();
}

async function doSync(row: Api.Waf.IpListSub) {
  const res = await syncIpListSub(row.id);
  window.$message?.success(`同步完成，拉取 ${res.data?.count ?? 0} 条`);
  await load();
}

// —— 表单 ——
const editOpen = ref(false);
const saving = ref(false);
const form = reactive<Partial<Api.Waf.IpListSub>>({ name: '', url: '', data: '', target: 'ip', type: 'blacklist', interval_min: 60, enabled: true });
const sourceMode = ref<'url' | 'manual'>('url');

function openCreate() {
  Object.assign(form, {
    id: undefined,
    name: '',
    url: '',
    target: activeTarget.value,
    type: 'blacklist',
    data: '',
    interval_min: 60,
    enabled: true
  });
  sourceMode.value = 'url';
  editOpen.value = true;
}
function openEdit(row: Api.Waf.IpListSub) {
  Object.assign(form, row);
  sourceMode.value = row.data ? 'manual' : 'url';
  editOpen.value = true;
}
async function save() {
  saving.value = true;
  try {
    if (form.id) {
      await updateIpListSub(form.id, form);
    } else {
      await createIpListSub(form);
    }
    window.$message?.success('已保存，将在下个同步周期自动拉取，也可手动同步');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  {
    title: '目标',
    key: 'target',
    width: 110,
    render: (row: Api.Waf.IpListSub) =>
      h(
        NTag,
        { size: 'small', bordered: false, type: row.target === 'ip' ? 'info' : row.target === 'fingerprint' ? 'warning' : 'success' },
        { default: () => targetMeta[row.target as Target]?.label || row.target }
      )
  },
  {
    title: '名单方向',
    key: 'type',
    width: 90,
    render: (row: Api.Waf.IpListSub) =>
      row.target === 'ip'
        ? h(NTag, { size: 'small', type: row.type === 'whitelist' ? 'success' : 'error', bordered: false }, { default: () => (row.type === 'whitelist' ? '白名单' : '黑名单') })
        : h('span', { class: 'text-xs text-[rgb(125,125,125)]' }, '—')
  },
  { title: '来源', key: 'url', minWidth: 200, render: (row: Api.Waf.IpListSub) => (row.data ? h('span', { class: 'text-xs' }, '手动输入 IP 列表') : h('span', { class: 'text-xs text-[rgb(125,125,125)]', style: { wordBreak: 'break-all' } }, row.url)) },
  { title: '周期(min)', key: 'interval_min', width: 90 },
  { title: '同步状态', key: 'last_status', width: 100, render: (row: Api.Waf.IpListSub) => row.last_status || '-' },
  { title: '条数', key: 'last_count', width: 70, render: (row: Api.Waf.IpListSub) => row.last_count ?? '-' },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: (row: Api.Waf.IpListSub) => h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 200,
    render: (row: Api.Waf.IpListSub) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => doSync(row) }, { default: () => '同步' }),
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => remove(row) },
          {
            trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }),
            default: () => '确认删除该订阅？同步产生的条目将一并移除'
          }
        )
      ])
  }
];

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">订阅库</h2>
        <p class="text-sm text-[rgb(125,125,125)]">远程威胁情报源订阅：IP 库 / 恶意指纹库 / 爬虫画像库，定时自动同步并下发引擎</p>
      </div>
      <NButton type="primary" @click="openCreate">新建订阅</NButton>
    </div>

    <NAlert type="info" :bordered="false" class="card-wrapper">
      同步后的条目可随时在各库页面手动修改（编辑/启停/删除）；「手动同步」立即拉取，后台每分钟自动检查到期订阅。
    </NAlert>

    <NTabs v-model:value="activeTarget" type="line">
      <NTabPane v-for="(meta, t) in targetMeta" :key="t" :name="t" :tab="meta.label">
        <p class="mb-3 text-xs text-[rgb(125,125,125)]">{{ meta.hint }}</p>
        <NCard :bordered="false" class="card-wrapper">
          <NDataTable :columns="columns" :data="filtered" :loading="loading" :bordered="false" size="small" />
        </NCard>
      </NTabPane>
    </NTabs>

    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑订阅' : '新建订阅'" class="w-[min(96vw,560px)]">
      <NForm :model="form" label-placement="left" label-width="110">
        <NFormItem label="名称" required>
          <NInput v-model:value="form.name" :placeholder="`如 ${targetMeta[activeTarget].label}情报组`" />
        </NFormItem>
        <NFormItem label="订阅目标" required>
          <NSelect
            :value="form.target ?? activeTarget"
            :options="[
              { label: '恶意/信任 IP 库', value: 'ip' },
              { label: '恶意指纹库', value: 'fingerprint' },
              { label: '爬虫画像库', value: 'bot_profile' },
              { label: 'JA4 客户端库', value: 'ja4_profile' }
            ]"
            @update:value="v => (form.target = v as string)"
          />
        </NFormItem>
        <NFormItem v-if="(form.target ?? activeTarget) === 'ip'" label="名单方向" required>
          <NSelect v-model:value="form.type" :options="[{ label: '黑名单（拦截）', value: 'blacklist' }, { label: '白名单（放行）', value: 'whitelist' }]" />
        </NFormItem>
        <template v-if="(form.target ?? activeTarget) === 'ip'">
          <NFormItem label="来源方式">
            <NRadioGroup v-model:value="sourceMode">
              <NRadio value="url" label="URL 订阅" />
              <NRadio value="manual" label="手动输入" />
            </NRadioGroup>
          </NFormItem>
        </template>
        <NFormItem v-if="sourceMode === 'url'" label="订阅 URL" :required="sourceMode === 'url'">
          <NInput v-model:value="form.url" :placeholder="targetMeta[(form.target ?? activeTarget) as Target].placeholder" />
        </NFormItem>
        <NFormItem v-else label="IP 列表" :required="sourceMode === 'manual'">
          <div class="w-full">
            <NInput v-model:value="form.data" type="textarea" :rows="5" placeholder="每行一个 IP 或 CIDR，如&#10;1.2.3.4&#10;10.0.0.0/8&#10;# 注释行" />
            <p class="mt-1 text-xs text-[rgb(125,125,125)]">保存后立即并入黑白名单下发；编辑或删除后重新同步即可更新</p>
          </div>
        </NFormItem>
        <NFormItem label="同步周期(min)">
          <NInputNumber v-model:value="form.interval_min" :min="5" />
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
  </div>
</template>
