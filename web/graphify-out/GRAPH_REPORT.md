# Graph Report - /home/pwd-vm/PWDnow/web  (2026-05-10)

## Corpus Check
- 90 files · ~161,635 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 649 nodes · 1173 edges · 69 communities detected
- Extraction: 78% EXTRACTED · 22% INFERRED · 0% AMBIGUOUS · INFERRED: 257 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]

## God Nodes (most connected - your core abstractions)
1. `DaemonClient` - 44 edges
2. `handleLogin()` - 31 edges
3. `importFromFile()` - 28 edges
4. `test()` - 25 edges
5. `generateUUID()` - 24 edges
6. `getMfaConfig()` - 22 edges
7. `csvImport()` - 21 edges
8. `saveMfaConfig()` - 19 edges
9. `SecureKeyStore` - 16 edges
10. `refreshMfa()` - 14 edges

## Surprising Connections (you probably didn't know these)
- `wipeVaultData()` --calls--> `handleTriggerWipe()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/securityModes.ts → /home/pwd-vm/PWDnow/web/src/pages/Settings.tsx
- `generateUUID()` --calls--> `handleAddNew()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/ManageFolders.tsx
- `generateUUID()` --calls--> `addEmail()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/AssetHolder.tsx
- `generateUUID()` --calls--> `addPhoneNumber()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/AssetHolder.tsx
- `generateUUID()` --calls--> `addU2fKey()`  [INFERRED]
  /home/pwd-vm/PWDnow/web/src/utils/crypto.ts → /home/pwd-vm/PWDnow/web/src/pages/AssetHolder.tsx

## Communities

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (63): generateRecoveryKey(), triggerDownload(), handleWebAuthnLogin(), authenticateWebAuthn(), authenticateWebAuthnForLogin(), authenticateWithPasskeyForLogin(), b64urlToBuf(), base32Decode() (+55 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (51): handleSubmit(), generateUUID(), buildKeePassXML(), buildPWDnowPayload(), crc32(), createSingleFileZip(), csvImport(), decryptPWDnowExport() (+43 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (40): appendAuditEvent(), auditLogPath(), authMiddleware(), compactIpInfo(), constEq(), decryptBlob(), derivedKey(), encryptBlob() (+32 more)

### Community 3 - "Community 3"
Cohesion: 0.06
Nodes (40): argon2idWasm(), loginFlow(), deriveArgon2idMaster(), deriveLocalKey(), deriveLocalKeys(), deriveV1Only(), getKdfWorker(), getOrCreateLocalKeySalt() (+32 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (5): DaemonClient, enrollQuickUnlock(), getQuickUnlockDbk(), revokeLocalQuickUnlock(), handleToggleQuickUnlock()

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (22): BufReader, BufWriter, buildPayload(), deriveKeysV2(), doubleEncrypt(), encodeEntry(), encodeFolder(), encodeMeta() (+14 more)

### Community 6 - "Community 6"
Cohesion: 0.14
Nodes (31): bytesToHex(), generateSalt(), hashEmail(), hashPassword(), hexToBytes(), armDuressMode(), bytesToHex(), checkIsDuressPassword() (+23 more)

### Community 7 - "Community 7"
Cohesion: 0.09
Nodes (16): AppLayout(), handleLogout(), clearMfaCache(), useNotification(), clearAllSessions(), handleLogout(), DecryptionPendingError, hasServerSession() (+8 more)

### Community 8 - "Community 8"
Cohesion: 0.17
Nodes (9): SecureKeyStore, decryptFromServer(), encryptForServer(), fromB64u(), readDecryptedLocal(), toB64u(), writeEncryptedLocal(), loadPasskeyHint() (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.15
Nodes (11): clearWithExec(), execWrite(), secureClipboard(), computeExpiryDate(), FaviconImage(), getFolderDescription(), getFolderTitle(), getServiceStyle() (+3 more)

### Community 10 - "Community 10"
Cohesion: 0.13
Nodes (8): consumeMfaToken(), mountAuthAndVault(), strF(), u32F(), computeSriForAssets(), getSriHtml(), isWsRateLimited(), computeHealth()

### Community 11 - "Community 11"
Cohesion: 0.15
Nodes (4): addEmail(), addPhoneNumber(), addU2fKey(), handleSave()

### Community 12 - "Community 12"
Cohesion: 0.27
Nodes (5): handleAddNew(), handleConfirmDelete(), handleDragEnd(), setSelectedCredentialIds(), toggleCredentialSelection()

### Community 13 - "Community 13"
Cohesion: 0.33
Nodes (5): buildWordlistSet(), checkPassword(), checkViaHibpApi(), loadWordlistFile(), runScan()

### Community 14 - "Community 14"
Cohesion: 0.48
Nodes (5): apiFetch(), getCsrfToken(), handleDisable(), handleRespond(), handleSave()

### Community 15 - "Community 15"
Cohesion: 0.29
Nodes (1): ErrorBoundary

### Community 16 - "Community 16"
Cohesion: 0.53
Nodes (4): timingSafeEq(), v1AttackOnV2File(), v1HmacOracleAttack(), v2HmacOracleAttack()

### Community 17 - "Community 17"
Cohesion: 0.33
Nodes (0): 

### Community 18 - "Community 18"
Cohesion: 0.4
Nodes (0): 

### Community 19 - "Community 19"
Cohesion: 0.4
Nodes (2): PublicHeader(), useTheme()

### Community 20 - "Community 20"
Cohesion: 0.6
Nodes (3): createShare(), encryptCredential(), getCsrfToken()

### Community 21 - "Community 21"
Cohesion: 0.5
Nodes (0): 

### Community 22 - "Community 22"
Cohesion: 0.5
Nodes (0): 

### Community 23 - "Community 23"
Cohesion: 0.5
Nodes (0): 

### Community 24 - "Community 24"
Cohesion: 0.5
Nodes (0): 

### Community 25 - "Community 25"
Cohesion: 0.67
Nodes (0): 

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (2): decryptBlob(), derivedKey()

### Community 27 - "Community 27"
Cohesion: 0.67
Nodes (0): 

### Community 28 - "Community 28"
Cohesion: 0.67
Nodes (0): 

### Community 29 - "Community 29"
Cohesion: 0.67
Nodes (0): 

### Community 30 - "Community 30"
Cohesion: 0.67
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

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (0): 

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (0): 

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (0): 

### Community 37 - "Community 37"
Cohesion: 1.0
Nodes (0): 

### Community 38 - "Community 38"
Cohesion: 1.0
Nodes (0): 

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (0): 

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (0): 

### Community 41 - "Community 41"
Cohesion: 1.0
Nodes (0): 

### Community 42 - "Community 42"
Cohesion: 1.0
Nodes (0): 

### Community 43 - "Community 43"
Cohesion: 1.0
Nodes (0): 

### Community 44 - "Community 44"
Cohesion: 1.0
Nodes (0): 

### Community 45 - "Community 45"
Cohesion: 1.0
Nodes (0): 

### Community 46 - "Community 46"
Cohesion: 1.0
Nodes (0): 

### Community 47 - "Community 47"
Cohesion: 1.0
Nodes (0): 

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (0): 

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (0): 

### Community 50 - "Community 50"
Cohesion: 1.0
Nodes (0): 

### Community 51 - "Community 51"
Cohesion: 1.0
Nodes (0): 

### Community 52 - "Community 52"
Cohesion: 1.0
Nodes (0): 

### Community 53 - "Community 53"
Cohesion: 1.0
Nodes (0): 

### Community 54 - "Community 54"
Cohesion: 1.0
Nodes (0): 

### Community 55 - "Community 55"
Cohesion: 1.0
Nodes (0): 

### Community 56 - "Community 56"
Cohesion: 1.0
Nodes (0): 

### Community 57 - "Community 57"
Cohesion: 1.0
Nodes (0): 

### Community 58 - "Community 58"
Cohesion: 1.0
Nodes (0): 

### Community 59 - "Community 59"
Cohesion: 1.0
Nodes (0): 

### Community 60 - "Community 60"
Cohesion: 1.0
Nodes (0): 

### Community 61 - "Community 61"
Cohesion: 1.0
Nodes (0): 

### Community 62 - "Community 62"
Cohesion: 1.0
Nodes (0): 

### Community 63 - "Community 63"
Cohesion: 1.0
Nodes (0): 

### Community 64 - "Community 64"
Cohesion: 1.0
Nodes (0): 

### Community 65 - "Community 65"
Cohesion: 1.0
Nodes (0): 

### Community 66 - "Community 66"
Cohesion: 1.0
Nodes (0): 

### Community 67 - "Community 67"
Cohesion: 1.0
Nodes (0): 

### Community 68 - "Community 68"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **Thin community `Community 31`** (2 nodes): `test_hash.js`, `bytesToHex()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (2 nodes): `mfa-enforcement.spec.ts`, `mockDaemon()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (2 nodes): `repro_folder_bug.spec.ts`, `login()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (2 nodes): `toB64u()`, `argon2_envelope.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (2 nodes): `NotificationDropdown.tsx`, `getTimeAgo()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (2 nodes): `UserAvatar.tsx`, `UserAvatar()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 37`** (2 nodes): `LanguageModal.tsx`, `handleSelect()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 38`** (2 nodes): `SEO.tsx`, `SEO()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (2 nodes): `EmergencyRequest()`, `EmergencyRequest.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `debug_test.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `run_debug.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `test-kdbx.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `playwright.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `repro_v2.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `screenshot-kdbx.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `test-fixes.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `repro_v3.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `test-wang.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `brave-verify.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 50`** (1 nodes): `folder-persist.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 51`** (1 nodes): `types.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 52`** (1 nodes): `vite-env.d.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 53`** (1 nodes): `main.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 54`** (1 nodes): `i18n.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (1 nodes): `kdf.worker.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (1 nodes): `keystore.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 57`** (1 nodes): `importExport.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 58`** (1 nodes): `mfa.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (1 nodes): `p2wPadding.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 60`** (1 nodes): `login_perf.bench.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (1 nodes): `crypto.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 62`** (1 nodes): `securityModes.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 63`** (1 nodes): `negative.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 64`** (1 nodes): `kdbx_test.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 65`** (1 nodes): `p2wFormat.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 66`** (1 nodes): `argon2.worker.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 67`** (1 nodes): `NotFound.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 68`** (1 nodes): `Dashboard.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `generateUUID()` connect `Community 1` to `Community 3`, `Community 5`, `Community 6`, `Community 11`, `Community 12`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Why does `handleLogin()` connect `Community 3` to `Community 0`, `Community 1`, `Community 2`, `Community 4`, `Community 6`, `Community 8`, `Community 10`?**
  _High betweenness centrality (0.122) - this node is a cross-community bridge._
- **Why does `test()` connect `Community 3` to `Community 0`, `Community 2`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Are the 28 inferred relationships involving `handleLogin()` (e.g. with `.get()` and `.reset()`) actually correct?**
  _`handleLogin()` has 28 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `importFromFile()` (e.g. with `isP2WFile()` and `importFromP2W()`) actually correct?**
  _`importFromFile()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 23 inferred relationships involving `test()` (e.g. with `verifyTotpCode()` and `parseUA()`) actually correct?**
  _`test()` has 23 INFERRED edges - model-reasoned connections that need verification._
- **Are the 23 inferred relationships involving `generateUUID()` (e.g. with `csvImport()` and `import1PUX()`) actually correct?**
  _`generateUUID()` has 23 INFERRED edges - model-reasoned connections that need verification._