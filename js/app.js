(function () {
  "use strict";

  var RDAP_BASE = "https://rdap.org";
  var COOLDOWN_MS = 2500;
  var lastLookupTime = 0;

  var form = document.getElementById("lookup-form");
  var input = document.getElementById("query-input");
  var btn = document.getElementById("lookup-btn");
  var rateLimitMsg = document.getElementById("rate-limit-msg");
  var loadingEl = document.getElementById("loading");
  var errorEl = document.getElementById("error");
  var resultsEl = document.getElementById("results");
  var summaryList = document.getElementById("summary-list");
  var rawToggle = document.getElementById("raw-toggle");
  var rawJson = document.getElementById("raw-json");

  // --- Helpers ---

  function isIP(str) {
    // Simple check: contains only digits and dots (IPv4) or contains colon (IPv6)
    return /^[\d.]+$/.test(str) || str.indexOf(":") !== -1;
  }

  function cleanDomain(str) {
    // Strip protocol and path if user pastes a URL
    str = str.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim().toLowerCase();
    return str;
  }

  function show(el) {
    el.classList.remove("hidden");
  }

  function hide(el) {
    el.classList.add("hidden");
  }

  function setError(msg) {
    errorEl.textContent = msg;
    show(errorEl);
  }

  function resetUI() {
    hide(loadingEl);
    hide(errorEl);
    hide(resultsEl);
    hide(rateLimitMsg);
    summaryList.innerHTML = "";
    rawJson.textContent = "";
    rawToggle.setAttribute("aria-expanded", "false");
    hide(rawJson);
  }

  // --- RDAP parsing ---

  function findVcard(entities, role) {
    if (!entities) return null;
    for (var i = 0; i < entities.length; i++) {
      var e = entities[i];
      if (e.roles && e.roles.indexOf(role) !== -1 && e.vcardArray) {
        return e.vcardArray;
      }
    }
    return null;
  }

  function vcardField(vcard, fieldName) {
    if (!vcard || !vcard[1]) return null;
    var fields = vcard[1];
    for (var i = 0; i < fields.length; i++) {
      if (fields[i][0] === fieldName) {
        return fields[i][3];
      }
    }
    return null;
  }

  function findEvent(events, action) {
    if (!events) return null;
    for (var i = 0; i < events.length; i++) {
      if (events[i].eventAction === action) {
        return events[i].eventDate;
      }
    }
    return null;
  }

  function formatDate(dateStr) {
    if (!dateStr) return null;
    try {
      var d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch (e) {
      return dateStr;
    }
  }

  function parseDomainResponse(data) {
    var fields = [];

    // Domain name
    if (data.ldhName) {
      fields.push(["Domain", data.ldhName]);
    }

    // Handle / name (for IPs)
    if (data.handle) {
      fields.push(["Handle", data.handle]);
    }

    // IP network
    if (data.startAddress && data.endAddress) {
      fields.push(["IP Range", data.startAddress + " \u2013 " + data.endAddress]);
    }
    if (data.name) {
      fields.push(["Network Name", data.name]);
    }

    // Registrant
    var registrantVcard = findVcard(data.entities, "registrant");
    var registrantName = vcardField(registrantVcard, "fn");
    if (registrantName) {
      fields.push(["Registrant", registrantName]);
    }

    // Registrar
    var registrarVcard = findVcard(data.entities, "registrar");
    var registrarName = vcardField(registrarVcard, "fn");
    if (registrarName) {
      fields.push(["Registrar", registrarName]);
    }

    // Also check for nested entities (common pattern: registrar is nested under registrant)
    if (!registrarName && data.entities) {
      for (var i = 0; i < data.entities.length; i++) {
        if (data.entities[i].roles && data.entities[i].roles.indexOf("registrar") !== -1) {
          // Try publicIds for registrar IANA ID
          if (data.entities[i].publicIds) {
            for (var j = 0; j < data.entities[i].publicIds.length; j++) {
              if (data.entities[i].publicIds[j].type === "IANA Registrar ID") {
                fields.push(["Registrar ID", data.entities[i].publicIds[j].identifier]);
              }
            }
          }
          // Try vcardArray
          if (data.entities[i].vcardArray) {
            var rName = vcardField(data.entities[i].vcardArray, "fn");
            if (rName) {
              fields.push(["Registrar", rName]);
            }
          }
        }
      }
    }

    // Dates
    var created = findEvent(data.events, "registration");
    var expires = findEvent(data.events, "expiration");
    var updated = findEvent(data.events, "last changed");

    if (created) fields.push(["Created", formatDate(created)]);
    if (updated) fields.push(["Updated", formatDate(updated)]);
    if (expires) fields.push(["Expires", formatDate(expires)]);

    // Nameservers
    if (data.nameservers && data.nameservers.length > 0) {
      var ns = data.nameservers
        .map(function (n) {
          return n.ldhName;
        })
        .filter(Boolean)
        .join(", ");
      if (ns) fields.push(["Nameservers", ns]);
    }

    // Status
    if (data.status && data.status.length > 0) {
      fields.push(["Status", data.status.join(", ")]);
    }

    // Port43 (traditional WHOIS server)
    if (data.port43) {
      fields.push(["WHOIS Server", data.port43]);
    }

    return fields;
  }

  function renderSummary(fields) {
    summaryList.innerHTML = "";
    if (fields.length === 0) {
      var dt = document.createElement("dt");
      dt.textContent = "Note";
      var dd = document.createElement("dd");
      dd.textContent = "No structured data available in RDAP response.";
      summaryList.appendChild(dt);
      summaryList.appendChild(dd);
      return;
    }
    for (var i = 0; i < fields.length; i++) {
      var dtEl = document.createElement("dt");
      dtEl.textContent = fields[i][0];
      var ddEl = document.createElement("dd");
      ddEl.textContent = fields[i][1];
      summaryList.appendChild(dtEl);
      summaryList.appendChild(ddEl);
    }
  }

  // --- Lookup ---

  function doLookup(query) {
    var now = Date.now();
    if (now - lastLookupTime < COOLDOWN_MS) {
      show(rateLimitMsg);
      return;
    }
    lastLookupTime = now;

    resetUI();
    show(loadingEl);
    btn.disabled = true;

    var endpoint;
    if (isIP(query)) {
      endpoint = RDAP_BASE + "/ip/" + encodeURIComponent(query);
    } else {
      endpoint = RDAP_BASE + "/domain/" + encodeURIComponent(query);
    }

    fetch(endpoint)
      .then(function (res) {
        if (!res.ok) {
          if (res.status === 404) {
            throw new Error(
              "Domain or IP not found in RDAP. It may not be registered, or the TLD may not support RDAP."
            );
          }
          throw new Error("RDAP lookup failed (HTTP " + res.status + ").");
        }
        return res.json();
      })
      .then(function (data) {
        hide(loadingEl);
        btn.disabled = false;

        var fields = parseDomainResponse(data);
        renderSummary(fields);
        rawJson.textContent = JSON.stringify(data, null, 2);
        show(resultsEl);
      })
      .catch(function (err) {
        hide(loadingEl);
        btn.disabled = false;

        var msg = err.message || "Lookup failed.";
        if (err.name === "TypeError" && msg.indexOf("fetch") !== -1) {
          msg =
            "Network error \u2014 CORS may be blocked or you are offline. Try: whois " +
            query +
            " in your terminal.";
        }
        setError(msg);
      });
  }

  // --- Events ---

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var query = cleanDomain(input.value);
    if (!query) return;
    input.value = query;
    doLookup(query);
  });

  rawToggle.addEventListener("click", function () {
    var expanded = rawToggle.getAttribute("aria-expanded") === "true";
    rawToggle.setAttribute("aria-expanded", String(!expanded));
    if (expanded) {
      hide(rawJson);
    } else {
      show(rawJson);
    }
  });

  // Expose pure functions for testing
  window._WhoisApp = {
    isIP: isIP,
    cleanDomain: cleanDomain,
    findVcard: findVcard,
    vcardField: vcardField,
    findEvent: findEvent,
    formatDate: formatDate,
    parseDomainResponse: parseDomainResponse,
  };
})();
