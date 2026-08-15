<script setup lang="ts">
import { h, onMounted, ref } from 'vue';
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
  NSelect,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  NAlert
} from 'naive-ui';
import {
  createAlertChannel,
  createAlertRule,
  deleteAlertChannel,
  deleteAlertRule,
  fetchAlertChannels,
  fetchAlertRules,
  testAlertChannel,
  updateAlertChannel,
  updateAlertRule
} from '@/service/api';
import { useMessage } from 'naive-ui';

const message = useMessage();
const channels = ref<Api.Waf.AlertChannel[]>([]);
const rules = ref<Api.Waf.AlertRule[]>([]);
const showChannelModal = ref(false);
const showRuleModal = ref(false);
type ChannelForm = Partial<Api.Waf.AlertChannel> & { secret?: string; smtp_pass?: string };
const editingChannel = ref<ChannelForm>({ type: 'webhook', enabled: true });
const editingRule = ref<Partial<Api.Waf.AlertRule>>({
  type: 'event_surge',
  window_sec: 60,
  threshold: 100,
  action: 'notify',
  cooldown_sec: 300,
  enabled: true
});

const channelTypes = [
  { label: '通用 Webhook', value: 'webhook' },
  { label: '钉钉', value: 'dingtalk' },
  { label: '企业微信', value: 'wecom' },
  { label: '飞书', value: 'feishu' },
  { label: '邮件 SMTP', value: 'email' }
];

async function load() {
  const [chs, rls] = await Promise.all([
    fetchAlertChannels().catch(() => ({ data: [] as Api.Waf.AlertChannel[] })),
    fetchAlertRules().catch(() => ({ data: [] as Api.Waf.AlertRule[] }))
  ]);
  channels.value = chs.data ?? [];
  rules.value = rls.data ?? [];
}
onMounted(load);

async function saveChannel() {
  const data = { ...editingChannel.value };
  if (data.id) {
    await updateAlertChannel(data.id, data);
  } else {
    await createAlertChannel(data);
  }
  message.success('已保存');
  showChannelModal.value = false;
  load();
}

function editChannel(row?: Api.Waf.AlertChannel) {
  editingChannel.value = row ? { ...row } : { type: 'webhook', enabled: true };
  showChannelModal.value = true;
}

async function onTestChannel(id: number) {
  try {
    await testAlertChannel(id);
    message.success('测试通知已发送，请检查接收端');
  } catch (e) {
    message.error('发送失败');
  }
}

async function saveRule() {
  const data = { ...editingRule.value };
  if (data.id) {
    await updateAlertRule(data.id, data);
  } else {
    await createAlertRule(data);
  }
  message.success('已保存');
  showRuleModal.value = false;
  load();
}

function editRule(row?: Api.Waf.AlertRule) {
  editingRule.value = row ? { ...row } : {
    type: 'event_surge', window_sec: 60, threshold: 100,
    action: 'notify', cooldown_sec: 300, enabled: true
  };
  showRuleModal.value = true;
}

const channelColumns = [
  { title: '名称', key: 'name' },
  { title: '类型', key: 'type', render: (row: Api.Waf.AlertChannel) => channelTypes.find(t => t.value === row.type)?.label || row.type },
  { title: '地址/主机', key: 'webhook_url', ellipsis: { tooltip: true } },
  {
    title: '状态',
    key: 'enabled',
    render: (row: Api.Waf.AlertChannel) =>
      row.enabled ? h(NTag, { type: 'success', size: 'small', bordered: false }, { default: () => '启用' })
        : h(NTag, { type: 'default', size: 'small', bordered: false }, { default: () => '停用' })
  },
  {
    title: '操作',
    key: 'actions',
    width: 190,
    render: (row: Api.Waf.AlertChannel) =>
      h('div', { class: 'flex gap-2' }, [
        h(NButton, { size: 'small', quaternary: true, onClick: () => onTestChannel(row.id) }, { default: () => '测试' }),
        h(NButton, { size: 'small', quaternary: true, onClick: () => editChannel(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => deleteAlertChannel(row.id).then(load) },
          { trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }), default: () => '确认删除该通道？' }
        )
      ])
  }
];

const ruleColumns = [
  { title: '名称', key: 'name' },
  { title: '类型', key: 'type', render: (row: Api.Waf.AlertRule) => (row.type === 'event_surge' ? '事件风暴' : '引擎离线') },
  { title: '条件', key: 'threshold', render: (row: Api.Waf.AlertRule) => `${row.window_sec}s 内 ${row.threshold} 条` },
  {
    title: '动作',
    key: 'action',
    render: (row: Api.Waf.AlertRule) =>
      row.action === 'rollback_rules' ? '通知 + 自动回滚规则' : '仅通知'
  },
  { title: '冷却(秒)', key: 'cooldown_sec' },
  {
    title: '启用',
    key: 'enabled',
    render: (row: Api.Waf.AlertRule) =>
      h(NSwitch, {
        value: row.enabled,
        onUpdateValue: v => updateAlertRule(row.id, { ...row, enabled: v }).then(load)
      })
  },
  {
    title: '操作',
    key: 'actions',
    width: 130,
    render: (row: Api.Waf.AlertRule) =>
      h('div', { class: 'flex gap-2' }, [
        h(NButton, { size: 'small', quaternary: true, onClick: () => editRule(row) }, { default: () => '编辑' }),
        h(
          NPopconfirm,
          { onPositiveClick: () => deleteAlertRule(row.id).then(load) },
          { trigger: () => h(NButton, { size: 'small', quaternary: true, type: 'error' }, { default: () => '删除' }), default: () => '确认删除该规则？' }
        )
      ])
  }
];
</script>

<template>
  <div class="space-y-4">
    <NAlert type="info" :bordered="false" class="card-wrapper">
      告警触发后经通知通道推送（Webhook/钉钉/企业微信/飞书/邮件）；「事件风暴」规则可配置自动回滚到最近一次规则发布快照。
    </NAlert>

    <NTabs type="line">
      <NTabPane name="channels" tab="通知通道">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NButton type="primary" size="small" @click="editChannel()">新建通道</NButton>
          </template>
          <NDataTable :columns="channelColumns" :data="channels" size="small" :bordered="false" />
        </NCard>
      </NTabPane>
      <NTabPane name="rules" tab="告警规则">
        <NCard :bordered="false" class="card-wrapper">
          <template #header-extra>
            <NButton type="primary" size="small" @click="editRule()">新建规则</NButton>
          </template>
          <NDataTable :columns="ruleColumns" :data="rules" size="small" :bordered="false" />
        </NCard>
      </NTabPane>
    </NTabs>

    <!-- 通道编辑弹窗 -->
    <NModal v-model:show="showChannelModal" preset="card" :title="editingChannel.id ? '编辑通道' : '新建通道'" style="width: 560px">
      <NForm label-placement="left" label-width="100">
        <NFormItem label="名称"><NInput v-model:value="editingChannel.name" placeholder="如：运维值班群" /></NFormItem>
        <NFormItem label="类型">
          <NSelect v-model:value="editingChannel.type" :options="channelTypes" />
        </NFormItem>
        <NFormItem v-if="editingChannel.type !== 'email'" label="Webhook URL">
          <NInput v-model:value="editingChannel.webhook_url" placeholder="https://oapi.dingtalk.com/robot/send?access_token=xxx" />
        </NFormItem>
        <NFormItem v-if="editingChannel.type !== 'email'" label="签名密钥">
          <NInput v-model:value="editingChannel.secret" placeholder="选填，留空保持不变" />
        </NFormItem>
        <template v-if="editingChannel.type === 'email'">
          <NFormItem label="SMTP 主机"><NInput v-model:value="editingChannel.smtp_host" placeholder="smtp.example.com" /></NFormItem>
          <NFormItem label="SMTP 端口"><NInputNumber v-model:value="editingChannel.smtp_port" :min="1" :max="65535" /></NFormItem>
          <NFormItem label="SMTP 用户"><NInput v-model:value="editingChannel.smtp_user" placeholder="user@example.com" /></NFormItem>
          <NFormItem label="SMTP 密码"><NInput v-model:value="editingChannel.smtp_pass" type="password" placeholder="留空保持不变" /></NFormItem>
          <NFormItem label="发件人"><NInput v-model:value="editingChannel.smtp_from" placeholder="user@example.com" /></NFormItem>
        </template>
        <NFormItem label="启用"><NSwitch v-model:value="editingChannel.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showChannelModal = false">取消</NButton>
          <NButton type="primary" @click="saveChannel">保存</NButton>
        </div>
      </template>
    </NModal>

    <!-- 规则编辑弹窗 -->
    <NModal v-model:show="showRuleModal" preset="card" :title="editingRule.id ? '编辑规则' : '新建规则'" style="width: 520px">
      <NForm label-placement="left" label-width="110">
        <NFormItem label="名称"><NInput v-model:value="editingRule.name" placeholder="如：攻击风暴告警" /></NFormItem>
        <NFormItem label="类型">
          <NSelect
            v-model:value="editingRule.type"
            :options="[
              { label: '事件风暴（窗口内攻击事件数超阈值）', value: 'event_surge' },
              { label: '引擎离线（全部引擎心跳超时）', value: 'engine_offline' }
            ]"
          />
        </NFormItem>
        <template v-if="editingRule.type === 'event_surge'">
          <NFormItem label="统计窗口(秒)"><NInputNumber v-model:value="editingRule.window_sec" :min="10" /></NFormItem>
          <NFormItem label="触发阈值"><NInputNumber v-model:value="editingRule.threshold" :min="1" /></NFormItem>
        </template>
        <NFormItem label="通知通道">
          <NSelect v-model:value="editingRule.channel_id" :options="channels.map(c => ({ label: c.name, value: c.id }))" />
        </NFormItem>
        <NFormItem label="处置动作">
          <NSelect
            v-model:value="editingRule.action"
            :options="[
              { label: '仅通知', value: 'notify' },
              { label: '通知 + 自动回滚最近一次规则发布', value: 'rollback_rules' }
            ]"
          />
        </NFormItem>
        <NFormItem label="冷却时间(秒)"><NInputNumber v-model:value="editingRule.cooldown_sec" :min="30" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="editingRule.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <div class="flex justify-end gap-2">
          <NButton @click="showRuleModal = false">取消</NButton>
          <NButton type="primary" @click="saveRule">保存</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>
