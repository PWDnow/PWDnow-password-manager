# Console Warnings Report
## Form Field Missing `id` or `name` Attribute

> **Browser Warning:** "A form field element has neither an id nor a name attribute. This might prevent the browser from correctly autofilling the form. To fix this issue, add a unique id or name attribute to a form field."

All warnings are of the same category: `<input>`, `<textarea>`, and `<select>` elements missing both the `id` and `name` attributes.

---

## Summary Table

| # | Page / Context | Element | Type | Placeholder / Description | Suggested `id` |
|---|---|---|---|---|---|
| 1 | Global (all pages) — Top navbar | `<input>` | `text` | `Search your sanctuary...` | `global-search` |
| 2 | `/vault` — All Items page body | `<input>` | `text` | `Search in All Items...` | `vault-search` |
| 3 | `/vault` — New/Edit Credential — LOGIN tab | `<input>` | `text` | `e.g. Free, Starter, Pro` (Account Type) | `account-type` |
| 4 | `/vault` — New/Edit Credential — LOGIN tab | `<textarea>` | — | `Add notes…` (Rich text notes editor) | `credential-notes` |
| 5 | `/vault` — New/Edit Credential — PASSKEY tab | `<input>` | `text` | `github.com` (RP ID / Domain) | `passkey-rpid` |
| 6 | `/vault` — New/Edit Credential — PASSKEY tab | `<input>` | `text` | `GitHub` (RP Name) | `passkey-rpname` |
| 7 | `/vault` — New/Edit Credential — PASSKEY tab | `<input>` | `text` | `base64url…` (Credential ID) | `passkey-credential-id` |
| 8 | `/vault` — New/Edit Credential — PASSKEY tab | `<input>` | `text` | `YubiKey 5C NFC` (Authenticator Name) | `passkey-authenticator` |
| 9 | `/vault` — New/Edit Credential — NOTE tab | `<textarea>` | — | `Write your secure note here…` | `note-content` |
| 10 | `/vault` — New/Edit Credential — CARD tab | `<input>` | `text` | `John Doe` (Cardholder Name) | `card-holder-name` |
| 11 | `/vault` — New/Edit Credential — CARD tab | `<input>` | `password` | `•••• •••• •••• ••••` (Card Number) | `card-number` |
| 12 | `/vault` — New/Edit Credential — CARD tab | `<input>` | `text` | `12/2028` (Expiry Date) | `card-expiry` |
| 13 | `/vault` — New/Edit Credential — CARD tab | `<input>` | `password` | `•••` (CVV) | `card-cvv` |
| 14 | `/vault` — New/Edit Credential — CARD tab | `<input>` | `text` | `123 Main St, City` (Billing Address) | `card-billing-address` |
| 15 | `/manage-folders` — Create/Edit Folder modal | `<input>` | `text` | `e.g. Personal, Gaming, Crypto` (Folder Name) | `folder-name` |
| 16 | `/manage-folders` — Create/Edit Folder modal | `<textarea>` | — | `What's inside this folder?` (Description) | `folder-description` |
| 17 | `/manage-folders` — Create/Edit Folder modal | `<textarea>` | — | `Paste SVG code here...` (Custom Icon) | `folder-svg-icon` |
| 18 | `/manage-folders` — Inline folder edit | `<input>` | `text` | *(folder name value, no placeholder)* | `folder-name-inline` |
| 19 | `/settings` — User Profile section | `<input type="file">` | `file` | *(avatar upload, hidden)* | `avatar-upload` |
| 20 | `/settings` — User Profile section | `<input>` | `text` | *(First Name field, no placeholder)* | `profile-first-name` |
| 21 | `/settings` — User Profile section | `<input>` | `text` | *(Last Name field, no placeholder)* | `profile-last-name` |
| 22 | `/settings` — User Profile section | `<input>` | `text` | `Enter company name...` | `profile-company` |
| 23 | `/settings` — Import section | `<input type="file">` | `file` | *(vault import file picker)* | `import-file` |
| 24 | `/settings` — Encryption section | `<input>` | `password` | `Enter a strong passphrase…` | `encryption-passphrase` |
| 25 | `/settings` — Encryption section | `<input>` | `password` | `Confirm passphrase…` | `encryption-passphrase-confirm` |
| 26 | `/settings` — Auto-lock section | `<select>` | — | *(Auto-lock timeout dropdown)* | `auto-lock-timeout` |
| 27 | `/settings` — Security section | `<select>` | — | *(Failed attempts lockout dropdown)* | `failed-attempts-limit` |
| 28 | `/security` — Breach Monitor page | `<input type="file">` | `file` | *(Custom wordlist upload, hidden)* | `breach-wordlist-upload` |
| 29 | `/asset-holder` — Asset Holder page | `<input>` | `email` | `name@example.com` (Email Address) | `asset-email` |
| 30 | `/asset-holder` — Asset Holder page | `<input>` | `tel` | `XXX-XXX-XXXX` (Phone Number) | `asset-phone` |
| 31 | `/asset-holder` — Asset Holder page | `<input>` | `text` | `Security Key Name` (U2F key label) | `asset-security-key-name` |

---

## Fields That Already Have `id` (for reference — no action needed)

These credential form fields already have proper `id` attributes and are **not** generating warnings:

| Field | Current `id` |
|---|---|
| Title / Service Name | `service-title` |
| Username / Email | `username` |
| Website URL | `website-url` |
| Password | `password-input` |

---

## Recommended Fixes

### 1. Global Search Bar (shared component — fix once, fixes all pages)
```html
<!-- Before -->
<input type="text" placeholder="Search your sanctuary..." />

<!-- After -->
<input type="text" id="global-search" name="global-search" placeholder="Search your sanctuary..." autocomplete="off" />
```

### 2. Vault Page — Inline Search Bar
```html
<input type="text" id="vault-search" name="vault-search" placeholder="Search in All Items..." autocomplete="off" />
```

### 3. /manage-folders — Create / Edit Folder modal
```html
<!-- Folder Name -->
<input type="text" id="folder-name" name="folder-name" placeholder="e.g. Personal, Gaming, Crypto" />

<!-- Description -->
<textarea id="folder-description" name="folder-description" placeholder="What's inside this folder?"></textarea>

<!-- Custom SVG Icon -->
<textarea id="folder-svg-icon" name="folder-svg-icon" placeholder="Paste SVG code here..."></textarea>

<!-- Inline edit input -->
<input type="text" id="folder-name-inline" name="folder-name-inline" />
```

### 4. /vault — New / Edit Credential — LOGIN tab
```html
<!-- Account Type -->
<input type="text" id="account-type" name="account-type" placeholder="e.g. Free, Starter, Pro" autocomplete="off" />

<!-- Notes textarea -->
<textarea id="credential-notes" name="credential-notes" rows="6"></textarea>
```

### 5. /vault — New / Edit Credential — PASSKEY tab
```html
<input type="text" id="passkey-rpid"          name="passkey-rpid"          placeholder="github.com" />
<input type="text" id="passkey-rpname"        name="passkey-rpname"        placeholder="GitHub" />
<input type="text" id="passkey-credential-id" name="passkey-credential-id" placeholder="base64url…" />
<input type="text" id="passkey-authenticator" name="passkey-authenticator" placeholder="YubiKey 5C NFC" />
```

### 6. /vault — New / Edit Credential — NOTE tab
```html
<textarea id="note-content" name="note-content" rows="12" placeholder="Write your secure note here…"></textarea>
```

### 7. /vault — New / Edit Credential — CARD tab
```html
<input type="text"     id="card-holder-name"     name="card-holder-name"     placeholder="John Doe"            autocomplete="cc-name" />
<input type="password" id="card-number"           name="card-number"           placeholder="•••• •••• •••• ••••" autocomplete="cc-number" />
<input type="text"     id="card-expiry"           name="card-expiry"           placeholder="12/2028"             autocomplete="cc-exp" maxlength="7" />
<input type="password" id="card-cvv"              name="card-cvv"              placeholder="•••"                 autocomplete="cc-csc" />
<input type="text"     id="card-billing-address"  name="card-billing-address"  placeholder="123 Main St, City"  autocomplete="street-address" />
```

### 8. /settings — User Profile
```html
<input type="file"   id="avatar-upload"      name="avatar-upload"      class="hidden" accept=".jpg,.jpeg,.png,.heic" />
<input type="text"   id="profile-first-name" name="profile-first-name" autocomplete="given-name" />
<input type="text"   id="profile-last-name"  name="profile-last-name"  autocomplete="family-name" />
<input type="text"   id="profile-company"    name="profile-company"    placeholder="Enter company name..." autocomplete="organization" />
```

### 9. /settings — Import
```html
<input type="file" id="import-file" name="import-file" class="sr-only" accept=".p2w,.json,.csv,.xml,.1pux,.1pif,.agilekeychain,.opvault,.dash,.kdbx,.kdb,.rbp,.enpassdb,.psafe3,.dat,.spdb" />
```

### 10. /settings — Encryption
```html
<input type="password" id="encryption-passphrase"         name="encryption-passphrase"         placeholder="Enter a strong passphrase…" autocomplete="new-password" />
<input type="password" id="encryption-passphrase-confirm" name="encryption-passphrase-confirm" placeholder="Confirm passphrase…"         autocomplete="new-password" />
```

### 11. /settings — Security Dropdowns
```html
<select id="auto-lock-timeout"    name="auto-lock-timeout"    aria-label="Auto-lock timeout">...</select>
<select id="failed-attempts-limit" name="failed-attempts-limit" aria-label="Failed attempts limit">...</select>
```

### 12. /security — Breach Monitor
```html
<input type="file" id="breach-wordlist-upload" name="breach-wordlist-upload" class="hidden" accept=".txt,.lst" />
```

### 13. /asset-holder — Asset Holder
```html
<input type="email" id="asset-email"             name="asset-email"             placeholder="name@example.com" autocomplete="email" />
<input type="tel"   id="asset-phone"             name="asset-phone"             placeholder="XXX-XXX-XXXX"     autocomplete="tel" />
<input type="text"  id="asset-security-key-name" name="asset-security-key-name" placeholder="Security Key Name" autocomplete="off" />
```

---

## Notes

- The **Global Search Bar** is a shared component rendered on every page — fixing it once will eliminate the warning across all routes simultaneously.
- `<input type="file">` fields also need `id`/`name` to be correctly associated with their `<label>` elements.
- `<select>` elements without `id`/`name` can break form submission and label association.
- Where semantically appropriate, `autocomplete` attribute suggestions are included to improve browser autofill accuracy.
- For password manager fields (card number, CVV), setting `autocomplete="off"` or the appropriate cc-* token is recommended to prevent accidental autofill.
