import DOMPurify from 'dompurify';

/**
 * Sanitize an SVG string and return a TrustedHTML object.
 *
 * Using RETURN_TRUSTED_TYPE satisfies the browser's Trusted Types enforcement
 * (requireTrustedTypesFor 'script' in CSP) for all dangerouslySetInnerHTML
 * sinks. Without this, plain strings passed to innerHTML are blocked.
 */
export function sanitizeSvg(dirty: string): TrustedHTML {
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { svg: true, svgFilters: true },
    RETURN_TRUSTED_TYPE: true,
  });
}

// Only <strong> <em> <u> <p> <br> - no attrs, no scripts, no links.
const DESC_CFG = { ALLOWED_TAGS: ['strong', 'em', 'u', 'p', 'br'], ALLOWED_ATTR: [] as string[] };

// For assigning to .innerHTML (Trusted Types enforcement requires TrustedHTML).
export function sanitizeDescriptionHtml(dirty: string): TrustedHTML {
  return DOMPurify.sanitize(dirty, { ...DESC_CFG, RETURN_TRUSTED_TYPE: true });
}

// For storing in the JSON credential blob (plain string).
export function sanitizeDescriptionString(dirty: string): string {
  return DOMPurify.sanitize(dirty, DESC_CFG);
}
