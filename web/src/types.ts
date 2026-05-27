export interface Folder {
  id: string;
  label: string;
  description?: string;
  iconName?: string;
  customSvg?: string;
}

export type CredentialType = 'login' | 'passkey' | 'secure_note' | 'payment_card';

export interface Credential {
  id: string | number;
  service: string;
  url: string;
  username: string;
  password?: string;
  status: string;
  statusColor: string;
  logo: string;
  folderId: string;
  tags?: string[];
  phoneNumber?: string | string[];
  kba?: { question: string; answer: string }[];
  u2fKeyName?: string | string[];
  otpSecret?: string;
  otpAlgorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  otpDigits?: number;
  accountType?: string;
  expiryEnabled?: boolean;
  expiryValue?: number;
  expiryUnit?: 'days' | 'months' | 'years';
  expiryNotifyEmail?: boolean;
  expirySetAt?: number;
  description?: string;
  // Credential type discriminant - undefined means 'login' for backwards compat
  credentialType?: CredentialType;
  // Passkey fields (credentialType === 'passkey')
  rpId?: string;
  rpName?: string;
  credentialId?: string;
  userHandle?: string;
  authenticatorName?: string;
  backedUp?: boolean;
  // Secure note fields (credentialType === 'secure_note')
  noteContent?: string;
  // Payment card fields (credentialType === 'payment_card')
  cardholderName?: string;
  cardNumber?: string;
  cardExpiry?: string;
  cardCvv?: string;
  cardBillingAddress?: string;
  cardType?: string;
  createdAt?: number;
  updatedAt?: number;
  customFields?: { id: string; label: string; value: string; isSecret: boolean }[];
  phone?: string;
  phoneCountry?: string;
}

export interface AssetHolder {
  emails: string[];
  phoneNumbers: string[];
  u2fKeys: string[];
}

export interface Notification {
  id: string;
  type: 'folder_created' | 'credential_added' | 'credential_deleted' | 'credential_expiring' | 'persistence_failed' | 'info' | 'success' | 'error';
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  data?: Record<string, unknown>;
}

export interface AuditEvent {
  id: string;
  action: string;
  success: boolean;
  ip: string;
  publicIp: string;
  ipInfo?: { city?: string; region?: string; country?: string; countryCode?: string; countryFlag?: string; org?: string };
  ts: number;
  riskFlags?: string[];
  resourceLabel?: string;
}

export interface ShareLink {
  id: string;
  label: string;
  createdAt: number;
  expiresAt: number;
  viewCount: number;
  singleView?: boolean;
  viewed?: boolean;
}

export interface EmailServerConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  secure?: boolean;
  protocol?: 'none' | 'ssl_tls' | 'starttls';
  fromName?: string;
}
