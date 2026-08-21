declare namespace Api {
  /**
   * namespace Auth
   *
   * backend api module: "auth"
   */
  namespace Auth {
    interface LoginToken {
      token: string;
      refreshToken?: string;
    }

    interface UserInfo {
      userId: string;
      userName: string;
      roles: string[];
      buttons: string[];
      /** 后端返回的用户名（/auth/me -> { id, username, role, totp_enabled }） */
      username?: string;
      /** 后端返回的角色（super/ops/viewer），映射到 roles */
      role?: string;
      /** 是否已启用 TOTP */
      totp_enabled?: boolean;
    }
  }
}
