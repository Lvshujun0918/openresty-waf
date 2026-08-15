import { request } from '../request';

/**
 * Login
 *
 * @param userName User name
 * @param password Password
 * @param totpCode TOTP 动态验证码（启用 TOTP 的账号必填）
 */
export function fetchLogin(userName: string, password: string, totpCode = '') {
  return request<Api.Auth.LoginToken>({
    url: '/auth/login',
    method: 'post',
    data: {
      username: userName,
      password,
      totp_code: totpCode
    }
  });
}

/** Get user info */
export function fetchGetUserInfo() {
  return request<Api.Auth.UserInfo>({ url: '/auth/me' });
}

/** 生成 TOTP 密钥（未确认前不生效） */
export function setupTotp() {
  return request<{ secret: string; otpauth_url: string }>({ url: '/auth/totp/setup', method: 'post' });
}

/** 校验动态码后启用 TOTP */
export function confirmTotp(code: string) {
  return request<{ status: string }>({ url: '/auth/totp/confirm', method: 'post', data: { code } });
}

/** 校验动态码后关闭 TOTP */
export function disableTotp(code: string) {
  return request<{ status: string }>({ url: '/auth/totp', method: 'delete', params: { code } });
}

/**
 * Refresh token
 *
 * @param refreshToken Refresh token
 */
export function fetchRefreshToken(refreshToken: string) {
  return request<Api.Auth.LoginToken>({
    url: '/auth/refreshToken',
    method: 'post',
    data: {
      refreshToken
    }
  });
}
