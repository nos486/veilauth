// Renders the Cloudflare Turnstile widget inside a same-origin frame and hands the token to the
// parent page with postMessage (docs/DECISIONS.md D-036). The site key and action come from the
// URL fragment; nothing else is read from the page.
"use strict";
(function () {
  var params = new URLSearchParams(location.hash.slice(1));
  var siteKey = params.get("sitekey") || "";
  var action = params.get("action") || "";
  function send(message) {
    if (window.parent !== window) window.parent.postMessage(message, location.origin);
  }
  window.veilauthTurnstileReady = function () {
    if (!/^[0-9A-Za-z_-]{1,64}$/.test(siteKey) || !/^[a-z-]{1,32}$/.test(action)) {
      send({ type: "turnstile", event: "error" });
      return;
    }
    window.turnstile.render("#widget", {
      sitekey: siteKey,
      action: action,
      callback: function (token) {
        send({ type: "turnstile", event: "token", token: token });
      },
      "expired-callback": function () {
        send({ type: "turnstile", event: "expired" });
      },
      "error-callback": function () {
        send({ type: "turnstile", event: "error" });
      },
    });
  };
})();
