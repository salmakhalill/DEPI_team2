/**
 * sanitize.js
 * Prevents Self-XSS by HTML-entity-encoding all user-supplied strings
 * before they are ever injected into the DOM via dangerouslySetInnerHTML.
 */
export function sanitize(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}
