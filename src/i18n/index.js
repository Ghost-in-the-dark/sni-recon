// Localisation engine.
//
// Deliberately tiny: a catalogue lookup, {placeholder} interpolation, and environment
// detection. No plural rules and no ICU — the tool's strings are labels, sentences and
// table headers, none of which need number-dependent forms in the shipped languages.
//
// A missing key falls back to English rather than throwing, so a partial translation
// degrades instead of crashing a scan that may already have taken minutes.
import en from './en.js';
import ru from './ru.js';

export const CATALOGUES = { en: en, ru: ru };
export const DEFAULT_LOCALE = 'en';
export const LOCALES = Object.keys(CATALOGUES);

/** Endonyms, for --lang listing and the TUI banner. */
export const LOCALE_NAMES = { en: 'English', ru: 'Русский' };

export function hasCatalogue(locale) {
  return Object.prototype.hasOwnProperty.call(CATALOGUES, String(locale));
}

export function catalogue(locale) {
  return hasCatalogue(locale) ? CATALOGUES[String(locale)] : CATALOGUES[DEFAULT_LOCALE];
}

/**
 * Reduce a POSIX or BCP-47 tag to a shipped locale.
 * Returns null when nothing matches, so callers can fall back deliberately.
 */
export function normalizeLocale(tag) {
  if (!tag || typeof tag !== 'string') return null;
  const base = tag
    .split(':')[0] // LANGUAGE=ru:en
    .split('.')[0] // ru_RU.UTF-8
    .split('@')[0]
    .trim()
    .toLowerCase()
    .replace(/_/g, '-');
  if (!base || base === 'c' || base === 'posix') return null;
  const primary = base.split('-')[0];
  return hasCatalogue(primary) ? primary : null;
}

/**
 * Detect the locale from the environment, in the precedence POSIX specifies.
 * LANGUAGE is only meaningful for LC_MESSAGES, but treating it as a weak hint after the
 * LC_* variables matches what users expect from a CLI.
 */
export function localeFromEnv(env) {
  const e = env || {};
  const order = [e.LC_ALL, e.LC_MESSAGES, e.LANG, e.LANGUAGE, e.LC_CTYPE];
  for (const candidate of order) {
    if (!candidate) continue;
    const hit = normalizeLocale(candidate);
    if (hit) return hit;
  }
  return DEFAULT_LOCALE;
}

function interpolate(template, params) {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, function (whole, key) {
    const value = params[key];
    if (value === undefined || value === null) return whole;
    return String(value);
  });
}

/** Translate one key for one locale. Never throws. */
export function translate(locale, key, params) {
  const cat = catalogue(locale);
  let template = cat[key];
  if (template === undefined) template = CATALOGUES[DEFAULT_LOCALE][key];
  if (template === undefined) return String(key);
  return interpolate(template, params);
}

/**
 * Bind a locale once and get a translator function back.
 * This is the object the report and CLI pass around.
 */
export function localizer(locale) {
  const resolved = hasCatalogue(locale) ? locale : DEFAULT_LOCALE;
  const t = function (key, params) {
    return translate(resolved, key, params);
  };
  t.locale = resolved;
  // NOT t.name: a function's own 'name' property is read-only in strict mode (every ES
  // module), so assigning it throws a TypeError at the first call.
  t.label = LOCALE_NAMES[resolved] || resolved;
  return t;
}

/** Human-readable list for --help. */
export function localeList() {
  return LOCALES.map(function (l) {
    return l + ' (' + LOCALE_NAMES[l] + ')' + (l === DEFAULT_LOCALE ? ' [default]' : '');
  }).join(', ');
}

export default { translate, localizer, localeFromEnv, normalizeLocale, LOCALES, LOCALE_NAMES };
