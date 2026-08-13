<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
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
  NSpace,
  NSwitch,
  NTag
} from 'naive-ui';
import {
  createCcRule,
  deleteCcRule,
  fetchCcRules,
  publishCcRules,
  setCcRuleEnabled,
  updateCcRule
} from '@/service/api';

const rules = ref<Api.Waf.CcRule[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const res = await fetchCcRules();
    rules.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function toggleEnabled(row: Api.Waf.CcRule) {
  await setCcRuleEnabled(row.id, !row.enabled);
  row.enabled = !row.enabled;
  window.$message?.success('已更新');
}

async function remove(row: Api.Waf.CcRule) {
  await deleteCcRule(row.id);
  window.$message?.success('已删除');
  await load();
}

async function doPublish() {
  await publishCcRules();
  window.$message?.success('CC 规则已发布，引擎 5 秒内热更新生效');
}

// —— 表单 ——
const editOpen = ref(false);
const saving = ref(false);
const form = reactive<Partial<Api.Waf.CcRule>>({ name: '', host: '', path: '', rate: '20r/s', ban_duration: 300, enabled: true });

function openCreate() {
  Object.assign(form, { id: undefined, name: '', host: '', path: '', rate: '20r/s', ban_duration: 300, enabled: true });
  editOpen.value = true;
}
function openEdit(row: Api.Waf.CcRule) {
  Object.assign(form, row);
  editOpen.value = true;
}
async function save() {
  saving.value = true;
  try {
    if (form.id) {
      await updateCcRule(form.id, form);
    } else {
      await createCcRule(form);
    }
    window.$message?.success('已保存');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  { title: '域名', key: 'host', width: 160, render: (row: Api.Waf.CcRule) => row.host || '-' },
  { title: '路径', key: 'path', width: 140, render: (row: Api.Waf.CcRule) => row.path || '-' },
  { title: '频率限制', key: 'rate', width: 110, render: (row: Api.Waf.CcRule) => h('span', { class: 'font-mono text-xs' }, row.rate) },
  {
    title: '封禁时长(s)',
    key: 'ban_duration',
    width: 110,
    render: (row: Api.Waf.CcRule) => row.ban_duration
  },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: (row: Api.Waf.CcRule) => h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 140,
    render: (row: Api.Waf.CcRule) =>
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

onMounted(load);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">CC 防刷</h2>
        <p class="text-sm text-[rgb(125,125,125)]">按域名 + 路径精细化频率限制，超限自动封禁 IP</p>
      </div>
      <NSpace>
        <NButton secondary type="warning" @click="doPublish">发布到引擎</NButton>
        <NButton type="primary" @click="openCreate">新建规则</NButton>
      </NSpace>
    </div>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="rules" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑 CC 规则' : '新建 CC 规则'" class="w-[min(96vw,560px)]">
      <NForm :model="form" label-placement="left" label-width="100">
        <NFormItem label="名称" required>
          <NInput v-model:value="form.name" placeholder="如 登录接口防刷" />
        </NFormItem>
        <NFormItem label="域名">
          <NInput v-model:value="form.host" placeholder="如 api.example.com（留空匹配全部）" />
        </NFormItem>
        <NFormItem label="路径">
          <NInput v-model:value="form.path" placeholder="如 /login（留空匹配全部）" />
        </NFormItem>
        <NFormItem label="频率限制" required>
          <NInput v-model:value="form.rate" placeholder="如 20r/s 或 100r/m" />
        </NFormItem>
        <NFormItem label="封禁时长(s)">
          <NInputNumber v-model:value="form.ban_duration" :min="1" />
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
