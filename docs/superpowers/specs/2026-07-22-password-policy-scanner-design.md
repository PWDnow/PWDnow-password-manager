# Browser Extension — In-Page Password Policy Scanner & Suggestion Design Spec

**Date:** 2026-07-22
**Status:** Approved
**Depends on:** `2026-07-21-browser-extension-design.md` (v1 extension), `2026-07-21-extension-ui-i18n-a11y-design.md` (enterprise UI/i18n/a11y overhaul, complete).
**Code location:** `~/Documents/PWDnow_extension` (same standalone repo).
**This is Sub-project B**, the piece explicitly deferred by both prior specs: "on a website, when I see things like a 'Password Requirements' popover, it should try to suggest a password and a strong one."

## 1. Goal

While browsing any website, when the extension detects a **new-password field** (account creation, password change — not an ordinary login field), it automatically shows a small inline banner suggesting a strong password that complies with that site's own detected rules (length range, required character classes), and lets the user fill it with one click and optionally save it to their PWDnow vault.

## 2. Architecture & permissions

This introduces a capability v1 deliberately didn't have: a **persistent content script** that runs on every page, not just on-demand injection triggered by a user action.

- `entrypoints/content.ts` — WXT `defineContentScript({ matches: ['<all_urls>'], runAt: 'document_idle' })`. Runs an initial DOM scan on load, then a `MutationObserver` on `document.body` (added/removed subtree changes) to catch SPA-rendered or lazily-mounted forms.
- **Permission consequence:** the manifest must add `host_permissions: ["<all_urls>"]` as a **required** permission (not the optional, one-time, origin-scoped grant v1 uses for the PWDnow server itself). This is a materially bigger install-time permission prompt ("Read and change all your data on all websites you visit") than anything the extension has asked for before — a direct, accepted consequence of "automatic, always-on" detection.
- The banner UI mounts into a **closed-mode Shadow DOM** root (`element.attachShadow({ mode: 'closed' })`) inserted as a sibling of the detected field, isolating it from the host page's CSS and JS, and reusing the same Tailwind design tokens (`app.css`) as the popup/options page.
- All content-script work (detection, parsing, generation) runs synchronously in-page — no relay-tab mechanism needed here (that mechanism exists only because *v1's* HTTP calls needed to run same-origin as the PWDnow server; this feature reads the *host page's own* DOM, which the content script is already injected into).
- Messaging to the background service worker is only needed for two things: (a) checking connection/unlocked status (`getStatus`, already exists) before offering to save, and (b) the save itself (`saveCredential`, already exists) — no new background logic required beyond routing these two existing message types from a content-script sender instead of only the popup.

## 3. Detecting a "new password" field (not a login field)

Signals-based heuristic in `lib/formDetector.ts`, a field group is treated as a new-password context if **any** of:
- Its `autocomplete` attribute is `"new-password"`.
- It is one of two (or more) adjacent `input[type="password"]` elements in the same form/container (password + confirm-password pattern).
- Nearby text (see below) matches signup/registration/change-password phrasing in English or the user's configured rule-detection language (§5) — e.g. "create a password", "confirm password", "choose a password", "set a new password".

A lone `input[type="password"]` with none of these signals (the ordinary login-form shape) is left alone — no banner.

**Nearby text collection** (`collectNearbyText(input)`): gathers text from `label[for=input.id]`, the element(s) referenced by `aria-describedby`, and sibling/parent text nodes within a bounded ancestor distance (fieldset/form/common wrapper divs, capped at ~3 levels up) — not a whole-page text scan.

## 4. Parsing the site's actual rules

`lib/passwordPolicy.ts` produces a `PasswordPolicy` (`minLength`, `maxLength`, `requireLower`, `requireUpper`, `requireDigit`, `requireSymbol`, optional `allowedSymbols`) from two sources, merged:

1. **HTML attributes** (`parsePolicyFromAttributes`): `minlength`, `maxlength`, `pattern` on the input itself — reliable when present, language-independent.
2. **Nearby visible text** (`parsePolicyFromText(text, lang)`): pattern-matches common rule phrasings ("8-100 characters", "at least one uppercase letter", "must contain a number", "special character required", etc.) against the text collected in §3.

**Language scope (per explicit user decision):** text-pattern sets are built for **all 13 extension languages** (en, fr, es, de, it, pt, ru, ar, hi, zh, ja, ko, id), not just English. Which language's patterns are active is controlled by a **dedicated setting independent of the popup's own UI language** (§5) — defaulting to English. If neither attributes nor text yield anything usable, fall back to a safe generic-strong policy (16 chars, all four classes required, a common safe symbol set) rather than guessing or declining to suggest anything.

**Generation** (`generateCompliantPassword(policy)` in `lib/passwordPolicy.ts`): builds on the existing `lib/passwordGenerator.ts`. That module's `generateCharsetPassword` currently hard-validates `length` to 8–64, which is correct for the popup's own manual Generate feature but too narrow for arbitrary site policies (a site might require max 12, or allow up to 100). The core character-selection loop is extracted into an unchecked `generateCharsetPasswordRaw(length, charset)`; `generateCharsetPassword` keeps its existing 8–64 validation (unchanged behavior for the popup), while `generateCompliantPassword` calls the raw function with a length clamped to the site's actual `[minLength, maxLength]` (itself clamped to a sane absolute floor/ceiling, e.g. 4–128, to avoid pathological output). If a policy is internally contradictory (e.g. `maxLength` too small to fit all required character classes), required classes are satisfied first and `maxLength` is treated as a hard ceiling — degrade quietly, never throw into the host page.

## 5. Settings (new options page)

A new WXT `options` entrypoint (`entrypoints/options/`, opened via right-click the extension icon → Options, or `chrome://extensions` → Details → Extension options) hosts two settings, persisted to `chrome.storage.local` via a new `lib/settings.ts`:

- **Suggest passwords automatically** — on/off toggle, default **on**.
- **Password rule detection language** — dropdown of all 13 languages (native names, same list/component pattern as the existing popup `LanguageSwitcher`), default **English**. This is deliberately **independent of the popup's own UI language setting** — you can browse the popup in English while telling the rule-parser to also recognize French phrasing, since these are different concerns (what language you read the extension in vs. what language a given website happens to phrase its rules in).

Since three separate entrypoints (popup, content script, options page) now each need their own i18n bootstrap, the i18n runtime module and the 13 locale JSON files move from `entrypoints/popup/i18n.ts` / `entrypoints/popup/locales/*.json` to a shared `lib/i18nRuntime.ts` / `lib/locales/*.json`, with the popup, content script, and options page each importing and calling the same `initI18n()`/`changeLanguage()` functions. This is a mechanical relocation (no behavior change) needed because the module is no longer popup-exclusive.

## 6. Banner UX

`entrypoints/content/Banner.tsx`, rendered into the Shadow DOM root, positioned via the target field's `getBoundingClientRect()` (`position: fixed`, repositioned on scroll/resize via a throttled listener).

- **Auto-shown** as soon as a qualifying field + policy is resolved (no click required to reveal it) — shows the generated password in a monospace field, a primary "Use this password" button, a "Regenerate" (refresh icon) button, and a small "×" dismiss button.
- **Use this password**: fills the password field (and confirm-password field, if present) using the same native-setter + `input`/`change` dispatch technique as `lib/fillScript.ts`'s `setNativeValue`; also fills the username/email field if one exists and already has a value. Immediately after, if `getStatus` reports connected+unlocked, shows a follow-up "Save to PWDnow vault?" confirmation (mirroring the popup's existing Save flow, via the existing `saveCredential` message) — if not connected, the fill happens but no save offer appears (nowhere to save to).
- **Regenerate**: re-runs `generateCompliantPassword` against the same resolved policy, replaces the displayed password. No length/charset controls in the banner itself — that's what the popup's own Generate screen already provides for manual control.
- **Dismiss (×)**: unmounts the banner for that specific field instance only (tracked in an in-memory `WeakSet` for the page's current lifetime — not persisted to storage). Reappears on next page load or for a different field; does not affect the global on/off setting.
- Respects the popup's UI language and RTL (Arabic) — this is the existing translated-UI-language concern, separate from the rule-detection-language setting in §5.

## 7. Error handling

- Shadow DOM mount and all DOM manipulation wrapped in try/catch — a failure here must never throw into the host page's own script execution; on failure, simply don't show a banner for that field.
- Contradictory/impossible policies degrade quietly per §4 (never surfaced as an error to the user).
- If messaging the background service worker fails (e.g. worker evicted), retry once; on continued failure show a small inline "Couldn't reach PWDnow — try the toolbar icon instead" state in the banner rather than a silent no-op or a thrown error.

## 8. Testing

- `lib/passwordPolicy.test.ts` — attribute parsing, text parsing (English plus a representative sample of the other 12 languages' equivalent phrasings), merge behavior, and `generateCompliantPassword` verified (run N times) to always produce output satisfying the resolved policy; contradictory-policy edge cases.
- `lib/formDetector.test.ts` — signals heuristic correctly rejects a login-form fixture and accepts signup-form fixtures (each of the three signal types independently); nearby-text collection is bounded and doesn't scan unrelated page content.
- `entrypoints/content/Banner.test.tsx` — Use/Regenerate/Dismiss wiring, `axe(container)` zero violations, translated strings, RTL.
- `entrypoints/content.test.ts` — scan+mount orchestration against jsdom fixture DOMs (mocked `chrome.storage`/`runtime` as elsewhere in this project): banner mounts for qualifying fixtures, does not mount for a login-form fixture.
- `entrypoints/options/*.test.tsx` — toggle and language-dropdown persist to storage; i18n/axe checks matching the existing component-test pattern.
- Manual E2E checklist gets new entries: a mocked signup-page fixture with visible rule text, a login-page fixture (banner must NOT appear), and an SPA-style lazily-rendered password field (MutationObserver must catch it).

## 9. Explicitly deferred

- Per-site permanent "never suggest on this domain" memory (only the global toggle + per-instance session dismiss from §6 are in scope).
- A length/charset adjustment control inside the banner itself (regenerate-only; full control remains the popup's existing Generate screen).
- Any change to v1's or the UI-overhaul's existing login/vault/fill/generate/save logic — this is a new, additive surface.
