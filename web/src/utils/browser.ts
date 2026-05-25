// Browser detection utilities

interface BraveNavigator extends Navigator {
  brave?: {
    isBrave(): Promise<boolean>;
  };
}

/** Returns true if the current browser is Brave. */
export async function isBraveBrowser(): Promise<boolean> {
  if (typeof navigator === 'undefined') return false;
  const n = navigator as BraveNavigator;
  return !!n.brave && typeof n.brave.isBrave === 'function' && (await n.brave.isBrave());
}
