import { request } from '../request';

/** 用户列表（仅超管） */
export function fetchUsers() {
  return request<Api.Waf.UserRow[]>({ url: '/users' });
}

/** 新建用户（仅超管） */
export function createUser(data: { username: string; password: string; role: string }) {
  return request<Api.Waf.UserRow>({ url: '/users', method: 'post', data });
}

/** 更新用户角色 / 重置密码（仅超管） */
export function updateUser(id: number, data: { role?: string; password?: string }) {
  return request<Api.Waf.UserRow>({ url: `/users/${id}`, method: 'put', data });
}

/** 删除用户（仅超管，不能删自己/最后一个超管由后端校验） */
export function deleteUser(id: number) {
  return request<{ ok: boolean }>({ url: `/users/${id}`, method: 'delete' });
}
