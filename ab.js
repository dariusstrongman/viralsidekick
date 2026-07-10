/* ViralSidekick lightweight A/B framework.
   abVariant(exp) -> sticky 'A'/'B' per visitor. abLog(exp,event,meta) -> engine sink + GA4.
   The engine (mode:'ab') writes events with the service key; this file never reads them. */
(function () {
  var API = 'https://n8n.stromation.com/webhook/viralsidekick-analyze';
  function vid() {
    try {
      var v = localStorage.getItem('vs_vid');
      if (!v) { v = Date.now().toString(36) + Math.random().toString(36).slice(2, 10); localStorage.setItem('vs_vid', v); }
      return v;
    } catch (e) { return 'x'; }
  }
  function assign(exp) {
    try {
      var m = JSON.parse(localStorage.getItem('vs_ab') || '{}');
      if (!m[exp]) { m[exp] = (Math.random() < 0.5 ? 'A' : 'B'); localStorage.setItem('vs_ab', JSON.stringify(m)); }
      return m[exp];
    } catch (e) { return 'A'; }
  }
  function seen(exp) {
    try {
      var s = JSON.parse(localStorage.getItem('vs_ab_seen') || '{}');
      if (exp) { s[exp] = 1; localStorage.setItem('vs_ab_seen', JSON.stringify(s)); }
      return s;
    } catch (e) { return {}; }
  }
  var sent = {};
  window.abVid = vid;
  window.abVariant = function (exp) { return assign(exp); };
  window.abLog = function (exp, event, meta) {
    var v = assign(exp);
    if (event === 'exposure') seen(exp); /* remember which experiments this visitor actually saw */
    try { if (window.gtag) window.gtag('event', 'ab_' + event, { experiment: exp, variant: v }); } catch (e) {}
    var k = exp + '|' + event;
    if (event === 'exposure') { if (sent[k]) return; sent[k] = 1; } /* one exposure per page load */
    try {
      fetch(API, { method: 'POST', headers: { 'Content-Type': 'application/json' }, keepalive: true,
        body: JSON.stringify({ mode: 'ab', vid: vid(), exp: exp, variant: v, event: event, meta: meta || null }) });
    } catch (e) {}
  };
  /* fire a conversion against every experiment this visitor has been exposed to (cross-page) */
  window.abConvert = function (event, meta) {
    var s = seen();
    Object.keys(s).forEach(function (exp) { window.abLog(exp, event, meta); });
  };
})();
