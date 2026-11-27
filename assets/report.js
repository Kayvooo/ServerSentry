"use strict";
(() => {
  const root = document.documentElement;
  const KEY = "serversentry-theme";
  const store = {
    get() { try { return localStorage.getItem(KEY); } catch (_) { return null; } },
    set(value) { try { localStorage.setItem(KEY, value); } catch (_) { /* storage may be blocked */ } },
  };
  const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  const systemTheme = () => (media && media.matches ? "light" : "dark");
  // Apply the theme immediately (before first paint) to avoid a flash; everything else waits for the DOM.
  const saved = store.get();
  root.dataset.theme = saved === "light" || saved === "dark" ? saved : systemTheme();
  if (media && media.addEventListener) {
    media.addEventListener("change", () => { if (!store.get()) { root.dataset.theme = systemTheme(); syncToggle(); } });
  }

  function syncToggle() {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    const light = root.dataset.theme === "light";
    button.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
    button.setAttribute("aria-pressed", String(light));
  }

  function init() {
    const $ = (selector, scope = document) => scope.querySelector(selector);
    const toggle = document.getElementById("theme-toggle");
    if (toggle) {
      toggle.hidden = false;
      toggle.addEventListener("click", () => {
        root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
        store.set(root.dataset.theme);
        syncToggle();
      });
      syncToggle();
    }

    // ---- Copy buttons (clipboard API with a textarea fallback for file:// pages) ----
    for (const button of document.querySelectorAll("[data-copy]")) {
      button.addEventListener("click", async () => {
        const value = button.dataset.copy;
        try { await navigator.clipboard.writeText(value); } catch (_) {
          const area = document.createElement("textarea");
          area.value = value; area.setAttribute("readonly", ""); area.style.position = "fixed"; area.style.opacity = "0";
          document.body.appendChild(area); area.select();
          try { document.execCommand("copy"); } finally { area.remove(); }
        }
        const label = $(".copy-label", button);
        if (label) { const old = label.textContent; label.textContent = "Copied"; setTimeout(() => { label.textContent = old; }, 1600); }
      });
    }

    // ---- Finding filters ----
    const search = document.getElementById("search");
    const cards = Array.from(document.querySelectorAll(".finding"));
    if (search) {
      // Cache text once; do not repeatedly traverse large evidence blocks while typing.
      const text = new Map(cards.map(card => [card, card.textContent.toLocaleLowerCase()]));
      const fields = ["status", "rule", "role", "channel", "state"];
      const controls = Object.fromEntries(fields.map(id => [id, document.getElementById(id)]).filter(pair => pair[1]));
      const severityButtons = Array.from(document.querySelectorAll("#severity-filter button"));
      const chips = Array.from(document.querySelectorAll(".comparison-counts button"));
      let severity = "";
      const count = document.getElementById("result-count");
      const empty = document.getElementById("no-results");
      const filter = () => {
        const query = search.value.trim().toLocaleLowerCase();
        let shown = 0;
        for (const card of cards) {
          const visible = (!query || text.get(card).includes(query))
            && (!severity || card.dataset.severity === severity)
            && fields.every(id => !controls[id] || !controls[id].value || card.dataset[id] === controls[id].value);
          card.hidden = !visible;
          if (visible) shown++;
        }
        for (const button of severityButtons) button.setAttribute("aria-pressed", String(button.dataset.value === severity));
        for (const chip of chips) chip.setAttribute("aria-pressed", String(!!controls.status && chip.dataset.status === controls.status.value));
        if (count) count.textContent = `${shown} of ${cards.length} findings`;
        if (empty && cards.length) empty.hidden = shown !== 0;
      };
      search.addEventListener("input", filter);
      for (const control of Object.values(controls)) control.addEventListener("input", filter);
      for (const button of severityButtons) button.addEventListener("click", () => { severity = button.dataset.value; filter(); });
      for (const chip of chips) {
        chip.addEventListener("click", () => {
          if (!controls.status) return;
          controls.status.value = controls.status.value === chip.dataset.status ? "" : chip.dataset.status;
          filter();
          document.getElementById("findings").scrollIntoView({ block: "start" });
        });
      }
      const reset = document.getElementById("reset");
      if (reset) reset.addEventListener("click", () => {
        search.value = ""; severity = "";
        for (const control of Object.values(controls)) control.value = "";
        filter();
      });
      const all = document.getElementById("toggle-all");
      if (all) all.addEventListener("click", () => {
        const open = all.getAttribute("aria-expanded") !== "true";
        for (const card of cards) if (!card.hidden) card.querySelector("details").open = open;
        all.setAttribute("aria-expanded", String(open));
        all.querySelector(".copy-label").textContent = open ? "Collapse all" : "Expand all";
      });
      document.addEventListener("keydown", event => {
        const tag = (event.target && event.target.tagName) || "";
        if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey && !/INPUT|SELECT|TEXTAREA/.test(tag)) {
          event.preventDefault(); search.focus();
        }
      });
      filter();
    }

    // ---- Object change search ----
    const changeSearch = document.getElementById("change-search");
    if (changeSearch) {
      const changes = Array.from(document.querySelectorAll(".change"));
      const changeText = new Map(changes.map(row => [row, row.textContent.toLocaleLowerCase()]));
      const filterChanges = () => {
        const query = changeSearch.value.trim().toLocaleLowerCase();
        let shown = 0;
        for (const row of changes) {
          row.hidden = !!query && !changeText.get(row).includes(query);
          if (!row.hidden) shown++;
        }
        document.getElementById("change-count").textContent = `${shown} of ${changes.length} object changes`;
        document.getElementById("changes-empty").hidden = shown !== 0 || changes.length === 0;
      };
      changeSearch.addEventListener("input", filterChanges);
      filterChanges();
    }

    // Printed or saved-as-PDF reports should contain the evidence, not collapsed summaries.
    let reopened = [];
    window.addEventListener("beforeprint", () => {
      reopened = Array.from(document.querySelectorAll("details:not([open])"));
      for (const item of reopened) item.open = true;
    });
    window.addEventListener("afterprint", () => { for (const item of reopened) item.open = false; reopened = []; });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
