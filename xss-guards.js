/**
 * Shared XSS reflection-sink guards.
 *
 * Unencoded reflection is only *exploitable* XSS when the payload lands in a
 * place the browser actually executes as HTML. These helpers cut the classic
 * false positives — "reflected in JSON/XML", "reflected inside an HTML
 * comment", "reflected inside a quoted attribute without breaking out", and
 * "payloads that are not executable HTML tokens at all".
 *
 * They are used by BOTH the deterministic scanner (scanner.js) and the
 * autonomous-agent detectors (agent/tools.js) so the two engines cannot drift
 * apart in what they consider a real sink.
 */

const XSS_EXEC_TOKEN = /<script|<\/script|<img|<svg|<iframe|<video|<audio|<details|<marquee|<object|<embed|<body|<form|<input|<button|<math|<a[^>]*href\s*=\s*["']?javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|onstart\s*=|onbegin\s*=|onpointerover\s*=|onloadstart\s*=|ontoggle\s*=|javascript:/i;

function hasExecutableXssToken(payload) {
    return XSS_EXEC_TOKEN.test(payload);
}

function isInsideHtmlComment(body, idx, payload = '') {
    const open = body.lastIndexOf('<!--', idx);
    if (open === -1) return false;
    const close = body.lastIndexOf('-->', idx);
    const insideAtReflection = close < open;
    if (!insideAtReflection || !payload) return insideAtReflection;

    // A payload can begin inside a comment and deliberately close it before
    // emitting an executable token (for example `text--><script>...`). Check
    // the token's final reflected context instead of rejecting at payload start.
    const tokenOffset = payload.search(XSS_EXEC_TOKEN);
    const commentCloseOffset = payload.indexOf('-->');
    if (tokenOffset < 0 || commentCloseOffset < 0 || tokenOffset < commentCloseOffset + 3) return true;
    return isInsideHtmlComment(body, idx + tokenOffset);
}

// True when `idx` sits inside a quoted HTML attribute value AND the payload
// does not contain the surrounding quote character (so it cannot break out).
// In that position the value is inert text: `<input value="<script>..">`
// does not execute anything.
//
// Guard against the classic false negative first: an unpaired quote in *prose*
// (e.g. "It's", "don't") is not an attribute delimiter. We therefore require
// the reflection point to be inside an open tag (a '<' with no '>' between it
// and `idx`) and only then consider quotes within that tag segment.
function isInsideQuotedAttribute(body, idx, payload) {
    const end = Math.max(0, idx);
    const tagStart = body.lastIndexOf('<', end - 1);
    const lastGt = body.lastIndexOf('>', end - 1);
    if (tagStart === -1 || lastGt > tagStart) return false; // in text, not a tag

    const tagSegment = body.slice(tagStart, end);
    const lastDouble = tagSegment.lastIndexOf('"');
    const lastSingle = tagSegment.lastIndexOf("'");
    if (lastDouble === -1 && lastSingle === -1) return false;

    const quote = lastDouble > lastSingle ? '"' : "'";
    const q = Math.max(lastDouble, lastSingle);
    const opens = (tagSegment.slice(0, q + 1).match(new RegExp('\\' + quote, 'g')) || []).length;
    if (opens % 2 === 0) return false;
    return !payload.includes(quote);
}

// A response is only renderable as HTML — and therefore a possible XSS sink —
// when it is served as HTML (or declares no content type at all, as many simple
// test/dev servers do). JSON/XML/JS bodies that merely contain the payload
// string are not executable.
function isRenderableHtml(contentType) {
    const ct = contentType || '';
    return ct === '' || /^text\/html/i.test(ct) || /^application\/xhtml\+xml/i.test(ct);
}

module.exports = {
    hasExecutableXssToken,
    isInsideHtmlComment,
    isInsideQuotedAttribute,
    isRenderableHtml,
};
