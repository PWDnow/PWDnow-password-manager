# Graph Report - /home/pwd-vm/PWDnow/web  (2026-04-22)

## Corpus Check
- 45 files · ~68,554 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 317 nodes · 512 edges · 34 communities detected
- Extraction: 78% EXTRACTED · 22% INFERRED · 0% AMBIGUOUS · INFERRED: 115 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]

## God Nodes (most connected - your core abstractions)
1. `DaemonClient` - 30 edges
2. `generateUUID()` - 16 edges
3. `handleLogin()` - 16 edges
4. `handleRegister()` - 13 edges
5. `test()` - 12 edges
6. `disableTravelMode()` - 12 edges
7. `hashPassword()` - 12 edges
8. `getMfaConfig()` - 10 edges
9. `enableTravelMode()` - 9 edges
10. `saveMfaConfig()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `handleTriggerWipe()` --calls--> `wipeVaultData()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/pages/Settings.tsx → /home/pwd-vm/PWDnow/web/src/utils/securityModes.ts
- `hashPassword()` --calls--> `handleNextStep()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/Settings.tsx
- `generateUUID()` --calls--> `handleAddNew()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/ManageFolders.tsx
- `generateUUID()` --calls--> `addEmail()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/AssetHolder.tsx
- `generateUUID()` --calls--> `addPhoneNumber()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/AssetHolder.tsx

## Communities

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (30): authenticateWebAuthn(), b64ToBytes(), b64urlToBuf(), base32Encode(), bufToB64url(), clearPendingOtp(), DEFAULT_MFA(), generateEmailCode() (+22 more)

### Community 1 - "Community 1"
Cohesion: 0.14
Nodes (30): bytesToHex(), generateSalt(), generateUUID(), hashEmail(), hashPassword(), hexToBytes(), handleLogin(), armDuressMode() (+22 more)

### Community 2 - "Community 2"
Cohesion: 0.1
Nodes (4): handleSave(), DaemonClient, handleConfirmUpdate(), handleSaveProfile()

### Community 3 - "Community 3"
Cohesion: 0.13
Nodes (21): authMiddleware(), decryptBlob(), derivedKey(), encryptBlob(), getClientIp(), initAuth(), issueJwt(), loadSessions() (+13 more)

### Community 4 - "Community 4"
Cohesion: 0.11
Nodes (14): checkViaHibpApi(), runScan(), deriveLocalKey(), getOrCreateLocalKeySalt(), SecureKeyStore, verifyTotp(), handleRegister(), validateEmail() (+6 more)

### Community 5 - "Community 5"
Cohesion: 0.17
Nodes (9): mountAuthAndVault(), defaults(), extractOtpSecret(), import1Password(), importBitwarden(), importFromFile(), importNordPass(), importPWDnow() (+1 more)

### Community 6 - "Community 6"
Cohesion: 0.22
Nodes (12): b64ToBytes(), bytesToB64(), readDecryptedLocal(), writeEncryptedLocal(), clearOtherSessions(), detectBrowserFromUA(), detectOSFromUA(), getSessions() (+4 more)

### Community 7 - "Community 7"
Cohesion: 0.16
Nodes (8): AppLayout(), useNotification(), loadLocalAssetHolder(), loadLocalCredentials(), loadLocalFolders(), _localRead(), useVault(), VaultProvider()

### Community 8 - "Community 8"
Cohesion: 0.21
Nodes (8): clearClipboardLater(), copyToClipboard(), FaviconImage(), getFolderDescription(), getFolderTitle(), getServiceStyle(), handleCopyPassword(), handleCopyUsername()

### Community 9 - "Community 9"
Cohesion: 0.17
Nodes (3): addEmail(), addPhoneNumber(), addU2fKey()

### Community 10 - "Community 10"
Cohesion: 0.22
Nodes (4): handleLogout(), clearMfaCache(), clearAllSessions(), handleLogout()

### Community 11 - "Community 11"
Cohesion: 0.27
Nodes (5): handleAddNew(), handleConfirmDelete(), handleDragEnd(), setSelectedCredentialIds(), toggleCredentialSelection()

### Community 12 - "Community 12"
Cohesion: 0.29
Nodes (3): constEq(), timingSafeEqual(), requireSetupToken()

### Community 13 - "Community 13"
Cohesion: 0.33
Nodes (1): ErrorBoundary

### Community 14 - "Community 14"
Cohesion: 0.33
Nodes (0): 

### Community 15 - "Community 15"
Cohesion: 0.4
Nodes (2): PublicHeader(), useTheme()

### Community 16 - "Community 16"
Cohesion: 0.5
Nodes (0): 

### Community 17 - "Community 17"
Cohesion: 0.5
Nodes (0): 

### Community 18 - "Community 18"
Cohesion: 0.67
Nodes (0): 

### Community 19 - "Community 19"
Cohesion: 0.67
Nodes (0): 

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (0): 

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (0): 

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (0): 

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (0): 

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (0): 

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (0): 

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (0): 

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (0): 

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (0): 

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (0): 

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (0): 

### Community 31 - "Community 31"
Cohesion: 1.0
Nodes (0): 

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (0): 

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **Thin community `Community 20`** (2 nodes): `test_hash.js`, `bytesToHex()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (2 nodes): `sanitize.ts`, `sanitizeSvg()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (2 nodes): `NotificationDropdown.tsx`, `getTimeAgo()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (2 nodes): `UserAvatar.tsx`, `UserAvatar()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (2 nodes): `LanguageModal.tsx`, `handleSelect()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (2 nodes): `SEO.tsx`, `SEO()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `vite.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `types.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `main.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `router.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `i18n.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (1 nodes): `crypto.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (1 nodes): `NotFound.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `Dashboard.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `generateUUID()` connect `Community 1` to `Community 4`, `Community 5`, `Community 6`, `Community 9`, `Community 11`?**
  _High betweenness centrality (0.141) - this node is a cross-community bridge._
- **Why does `DaemonClient` connect `Community 2` to `Community 10`, `Community 4`, `Community 5`?**
  _High betweenness centrality (0.099) - this node is a cross-community bridge._
- **Why does `handleLogin()` connect `Community 1` to `Community 0`, `Community 2`, `Community 4`, `Community 6`, `Community 12`?**
  _High betweenness centrality (0.097) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `generateUUID()` (e.g. with `importBitwarden()` and `import1Password()`) actually correct?**
  _`generateUUID()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `handleLogin()` (e.g. with `getDuressModeConfig()` and `checkIsDuressPassword()`) actually correct?**
  _`handleLogin()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Are the 11 inferred relationships involving `handleRegister()` (e.g. with `test()` and `.checkPasswordBreached()`) actually correct?**
  _`handleRegister()` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `test()` (e.g. with `parseUA()` and `deriveLocalKey()`) actually correct?**
  _`test()` has 10 INFERRED edges - model-reasoned connections that need verification._