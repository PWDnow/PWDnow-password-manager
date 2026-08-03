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
