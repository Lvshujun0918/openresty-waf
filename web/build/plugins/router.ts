import type { RouteMeta } from 'vue-router';
import ElegantVueRouter from '@elegant-router/vue/vite';
import type { RouteKey } from '@elegant-router/types';

/**
 * 菜单元信息单一事实源：图标/排序/权限随路由名注入。
 * 插件对已存在 routes.ts 条目只补缺失 meta（现有优先），
 * 因此本表在路由改名后首次生成时生效，写入后由 merge 持久保留。
 */
const ROUTE_META_MAP: Partial<Record<RouteKey, Partial<RouteMeta>>> = {
  // 常量/隐藏页不进菜单（上游默认手写 hideInMenu，纯再生成的场景由本表兜底）
  login: { hideInMenu: true },
  '403': { hideInMenu: true },
  '404': { hideInMenu: true },
  '500': { hideInMenu: true },
  'iframe-page': { hideInMenu: true },
  home: { icon: 'mdi:monitor-dashboard', order: 1, hideInMenu: true },
  dashboard: { icon: 'mdi:view-dashboard', order: 2 },
  // 安全监测
  monitoring: { icon: 'mdi:radar', order: 3 },
  monitoring_monitor: { icon: 'mdi:pulse', order: 1 },
  monitoring_traffic: { icon: 'mdi:swap-vertical', order: 2 },
  monitoring_events: { icon: 'mdi:shield-alert', order: 3 },
  'monitoring_error-logs': { icon: 'mdi:alert-circle-outline', order: 4 },
  // 防护策略
  protection: { icon: 'mdi:shield-half-full', order: 4 },
  protection_rules: { icon: 'mdi:shield-check-outline', order: 1 },
  'protection_rule-subs': { icon: 'mdi:cloud-download-outline', order: 2 },
  'protection_trigger-rules': { icon: 'mdi:tune', order: 3 },
  'protection_trigger-records': { icon: 'mdi:history', order: 4 },
  'protection_rule-perf': { icon: 'mdi:speedometer', order: 5 },
  // 封禁拦截
  blocking: { icon: 'mdi:block-helper', order: 5 },
  blocking_bans: { icon: 'mdi:cancel', order: 1 },
  'blocking_ip-lists': { icon: 'mdi:ip-network-outline', order: 2 },
  blocking_bots: { icon: 'mdi:robot-outline', order: 3 },
  'blocking_block-pages': { icon: 'mdi:file-alert-outline', order: 4 },
  alerts: { icon: 'mdi:bell-ring-outline', order: 6 },
  // 系统管理
  system: { icon: 'mdi:cog-outline', order: 7 },
  system_security: { icon: 'mdi:shield-key-outline', order: 1 },
  system_config: { icon: 'mdi:application-cog-outline', order: 2 },
  'system_audit-logs': { icon: 'mdi:clipboard-text-outline', order: 3 },
  system_users: { icon: 'mdi:account-multiple', order: 4, roles: ['super'] },
  'system_api-tokens': { icon: 'mdi:key-variant', order: 5, roles: ['super'] },
  guide: { icon: 'mdi:book-open-variant', order: 8 }
};

export function setupElegantRouter() {
  return ElegantVueRouter({
    layouts: {
      base: 'src/layouts/base-layout/index.vue',
      blank: 'src/layouts/blank-layout/index.vue'
    },
    routePathTransformer(routeName, routePath) {
      const key = routeName as RouteKey;

      if (key === 'login') {
        const modules: UnionKey.LoginModule[] = ['pwd-login', 'code-login', 'register', 'reset-pwd', 'bind-wechat'];

        const moduleReg = modules.join('|');

        return `/login/:module(${moduleReg})?`;
      }

      return routePath;
    },
    onRouteMetaGen(routeName) {
      const key = routeName as RouteKey;

      const constantRoutes: RouteKey[] = ['login', '403', '404', '500'];

      const meta: Partial<RouteMeta> = {
        title: key,
        i18nKey: `route.${key}` as App.I18n.I18nKey
      };

      if (constantRoutes.includes(key)) {
        meta.constant = true;
      }

      // 菜单元信息单一事实源：图标/排序/权限在再生成后依然存活
      const extra = ROUTE_META_MAP[key];
      if (extra) {
        Object.assign(meta, extra);
      }

      return meta;
    }
  });
}
