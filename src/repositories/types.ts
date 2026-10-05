export type UserStatus =
  "PENDING" | "ACTIVE" | "SUSPENDED" | "BLOCKED" | "DEACTIVATED";
export type CredentialType = "PASSWORD" | "LOGIN_PASSCODE" | "PIN" | "PASSKEY";

export interface UserRecord {
  id: string;
  tenant_id: string;
  user_type: "CUSTOMER" | "SERVICE_ACCOUNT";
  status: UserStatus;
  phone: string | null;
  email: string | null;
  phone_normalized: string | null;
  email_normalized: string | null;
  failed_login_attempts: number;
  locked_until: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface CredentialRecord {
  id: string;
  tenant_id: string;
  user_id: string;
  credential_type: CredentialType;
  credential_hash: string;
  credential_version: number;
  is_active: boolean;
  expires_at: Date | null;
}

export interface SessionRecord {
  id: string;
  tenant_id: string | null;
  user_id: string | null;
  subject_id: string;
  device_id: string | null;
  session_token_hash: string;
  refresh_token_hash: string | null;
  token_family_id: string;
  rotation_sequence: number;
  audience: string;
  subject_type: "CUSTOMER" | "ADMINISTRATOR";
  scope_type: "TENANT" | "PLATFORM";
  authorization_version: number | null;
  authentication_methods: string[];
  expires_at: Date;
  idle_expires_at: Date | null;
  revoked_at: Date | null;
  reuse_detected_at: Date | null;
  compromised_at: Date | null;
  replaced_by_session_id: string | null;
}
