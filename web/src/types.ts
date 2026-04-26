export interface Folder {
  id: string;
  label: string;
  description?: string;
  iconName?: string;
  customSvg?: string;
}

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
}

export interface AssetHolder {
  emails: string[];
  phoneNumbers: string[];
  u2fKeys: string[];
}

export interface Notification {
  id: string;
  type: 'folder_created' | 'credential_added' | 'credential_deleted';
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  data?: any;
}
