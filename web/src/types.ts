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
}

export interface AssetHolder {
  emails: string[];
  phoneNumbers: string[];
  u2fKeys: string[];
}

export interface Notification {
  id: string;
  type: 'folder_created' | 'credential_added' | 'credential_deleted' | 'credential_expiring' | 'persistence_failed';
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  data?: Record<string, unknown>;
}
