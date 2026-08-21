import { request } from '../request';

/** API Token 列表 */
export function fetchTokens() {
  return request<Api.Waf.ApiToken[]>({ url: '/tokens' });
}

/** 新建 API Token（明文 token 仅此一次返回） */
export function createToken(data: { name: string }) {
  return request<{ id: number; name: string; prefix: string; token: string }>({ url: '/tokens', method: 'post', data });
}

/** 吊销 API Token（软删除） */
export function revokeToken(id: number) {
  return request<{ ok: boolean }>({ url: `/tokens/${id}`, method: 'delete' });
}
