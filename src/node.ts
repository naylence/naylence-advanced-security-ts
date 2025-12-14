/**
 * Node-centric entry point for Naylence Advanced Security.
 *
 * Includes the full factory surface area, including certificate authority
 * helpers that rely on Node.js built-ins.
 */

import plugin from './plugin.js';

// Always register the plugin directly. This ensures it is initialized even if
// the dynamic import mechanism (used by FAME_PLUGINS) fails.
(async () => {
  try {
    await plugin.register();
  } catch (err) {
    console.error('[naylence:advanced-security] Failed to auto-register plugin:', err);
  }
})();

const g = (typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : {}) as any;
const proc = g.process || (typeof process !== 'undefined' ? process : undefined);
const isNode =
  typeof process !== 'undefined' &&
  process.versions != null &&
  process.versions.node != null;

// Only in Node.js: populate FAME_PLUGINS so child processes inherit it.
if (isNode && proc && proc.env) {
  const pluginName = '@naylence/advanced-security';
  const current = proc.env.FAME_PLUGINS || '';
  const plugins = current.split(',').map((p: string) => p.trim());
  if (!plugins.includes(pluginName)) {
    proc.env.FAME_PLUGINS = current
      ? `${current},${pluginName}`
      : pluginName;
  }
}

export * from "./advanced-security-isomorphic.js";

export * from "./naylence/fame/security/index.js";
export * from "./naylence/fame/stickiness/index.js";
export * from "./naylence/fame/welcome/index.js";
