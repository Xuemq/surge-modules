/* Original generic Surge response-header adapter. No network, logging, or storage.
 * Use only with separately reviewed URL patterns and exact argument values.
 * https://manual.nssurge.com/scripting/http-response.html
 */
(function () {
  let result = {};
  try {
    const argument = typeof $argument === 'string' && $argument.startsWith('uri:')
      ? decodeURIComponent($argument.slice(4)) : $argument;
    const spec = JSON.parse(argument);
    const names = spec.headerNames;
    const words = spec.keywords;
    const valid = Object.keys(spec).sort().join(',') === 'headerNames,keywords,status'
      && spec.status === 404
      && Array.isArray(names) && names.length > 0 && names.length <= 8
      && names.every(name => typeof name === 'string' && /^[A-Za-z0-9_-]+$/.test(name))
      && Array.isArray(words) && words.length > 0 && words.length <= 16
      && words.every(word => typeof word === 'string' && word.length > 0 && word.length <= 128);
    if (valid && typeof $request === 'object' && $request !== null
        && typeof $request.headers === 'object' && $request.headers !== null) {
      // Preserve the reviewed header spelling, priority, and case-sensitive match.
      let value;
      for (const name of names) {
        if ($request.headers[name]) { value = $request.headers[name]; break; }
      }
      if (typeof value === 'string' && words.some(word => value.includes(word))) {
        result = {status: 404};
      }
    }
  } catch (_) {
    // Missing/malformed policy or context leaves the original response untouched.
  }
  $done(result);
}());
