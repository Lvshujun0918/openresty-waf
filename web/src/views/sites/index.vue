<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import {
  NAlert,
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSpace,
  NSwitch,
  NTag
} from 'naive-ui';
import { createSite, deleteSite, fetchSites, updateSite } from '@/service/api';

const sites = ref<Api.Waf.Site[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const res = await fetchSites();
    sites.value = res.data ?? [];
  } finally {
    loading.value = false;
  }
}

async function toggleEnabled(row: Api.Waf.Site) {
  await updateSite(row.id, { ...row, enabled: !row.enabled });
  row.enabled = !row.enabled;
  window.$message?.success('已更新');
}

async function remove(row: Api.Waf.Site) {
  await deleteSite(row.id);
  window.$message?.success('已删除，归属规则已重置为全局规则');
  await load();
}

// —— 表单 ——
const editOpen = ref(false);
const saving = ref(false);
const form = reactive<Partial<Api.Waf.Site>>({ name: '', domain: '', enabled: true });

function openCreate() {
  Object.assign(form, { id: undefined, name: '', domain: '', enabled: true });
  editOpen.value = true;
}
function openEdit(row: Api.Waf.Site) {
  Object.assign(form, row);
  editOpen.value = true;
}
async function save() {
  saving.value = true;
  try {
    if (form.id) {
      await updateSite(form.id, form);
    } else {
      await createSite(form);
    }
    window.$message?.success('已保存');
    editOpen.value = false;
    await load();
  } finally {
    saving.value = false;
  }
}

const columns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name', minWidth: 140, ellipsis: { tooltip: true } },
  {
    title: '域名',
    key: 'domain',
    minWidth: 200,
    render: (row: Api.Waf.Site) => h('span', { class: 'font-mono text-sm' }, row.domain)
  },
  {
    title: '启用',
    key: 'enabled',
    width: 80,
    render: (row: Api.Waf.Site) =>
      h(NSwitch, { value: row.enabled, onUpdateValue: () => toggleEnabled(row) })
  },
  {
    title: '操作',
    key: 'action',
    width: 140,
    render: (row: Api.Waf.Site) =>
      h(NSpace, { size: 4 }, [
        h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => remove(row) },
          {
            trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }),
            default: () => '确认删除该站点？'
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
        <h2 class="text-xl font-semibold">站点管理</h2>
        <p class="text-sm text-[rgb(125,125,125)]">登记受保护域名，实现多站点规则隔离</p>
      </div>
      <NButton type="primary" @click="openCreate">新建站点</NButton>
    </div>

    <NAlert type="info" :bordered="false">
      规则可在「规则管理」中设置归属站点：站点规则仅对对应域名生效（按请求 Host 匹配），
      未归属站点的规则为全局规则。修改归属后需在规则管理页「发布到引擎」生效。
    </NAlert>

    <NCard :bordered="false" class="card-wrapper">
      <NDataTable :columns="columns" :data="sites" :loading="loading" :bordered="false" size="small" />
    </NCard>

    <NModal v-model:show="editOpen" preset="card" :title="form.id ? '编辑站点' : '新建站点'" class="w-[min(96vw,480px)]">
      <NForm :model="form" label-placement="left" label-width="80">
        <NFormItem label="名称" required>
          <NInput v-model:value="form.name" placeholder="如 主站 / 阅读站" />
        </NFormItem>
        <NFormItem label="域名" required>
          <NInput v-model:value="form.domain" placeholder="如 cszj.wang（不带端口与协议）" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="form.enabled" />
          <span class="text-xs text-[rgb(125,125,125)] ml-2">停用后该站点的专属规则不再下发</span>
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
