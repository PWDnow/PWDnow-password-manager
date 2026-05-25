import { logger } from './logger';
export async function enrollQuickUnlock(userId: string): Promise<Uint8Array | null> {
  if (!window.PublicKeyCredential) return null;
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userHandle = new TextEncoder().encode(userId);
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));

  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'PWDnow', id: window.location.hostname },
        user: { id: userHandle, name: userId, displayName: userId },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        },
        extensions: {
          prf: {
            eval: { first: prfSalt },
          }
        } as any
      }
    }) as PublicKeyCredential;

    const extResults = cred.getClientExtensionResults() as any;
    if (!extResults.prf?.enabled) {
      logger.warn('PRF not enabled by authenticator');
      return null; // PRF not supported
    }

    // Save the credential ID and the salt used for PRF to local storage
    const credId = Array.from(new Uint8Array(cred.rawId));
    const saltArray = Array.from(prfSalt);
    localStorage.setItem('_pwd_qu_cred', JSON.stringify({ id: credId, salt: saltArray }));

    return new Uint8Array(extResults.prf.results.first);
  } catch (e) {
    logger.error('Quick unlock enrollment failed', e);
    return null;
  }
}

export async function getQuickUnlockDbk(): Promise<Uint8Array | null> {
  const stored = localStorage.getItem('_pwd_qu_cred');
  if (!stored) return null;
  let data;
  try {
    data = JSON.parse(stored);
  } catch { return null; }
  
  const credId = new Uint8Array(data.id);
  const prfSalt = new Uint8Array(data.salt);
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: window.location.hostname,
        allowCredentials: [{
          id: credId,
          type: 'public-key',
        }],
        userVerification: 'required',
        extensions: {
          prf: {
            eval: { first: prfSalt },
          }
        } as any
      }
    }) as PublicKeyCredential;

    const extResults = assertion.getClientExtensionResults() as any;
    if (!extResults.prf?.results?.first) {
      return null;
    }
    return new Uint8Array(extResults.prf.results.first);
  } catch (e) {
    logger.error('Quick unlock failed', e);
    return null;
  }
}

export function hasLocalQuickUnlock(): boolean {
  return !!localStorage.getItem('_pwd_qu_cred');
}

export function revokeLocalQuickUnlock(): void {
  localStorage.removeItem('_pwd_qu_cred');
}
