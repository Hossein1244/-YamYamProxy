/* script.js
 * تمام منطق سمت کلاینت سایت: بارگذاری brand.json / status.json / servers.json،
 * نمایش آمار، فیلتر و جستجوی سرورها، QR Code، کپی لینک و Deep Link برنامه‌ها.
 * هیچ اطلاعاتی از کاربر ذخیره یا ردیابی نمی‌شود.
 */
(() => {
  "use strict";

  const state = {
    brand: null,
    status: null,
    servers: [],
    filtered: [],
  };

  const HEX_COLOR_RE = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;

  async function fetchJSON(path, fallback) {
    try {
      const res = await fetch(path, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`could not load ${path}:`, err);
      return fallback;
    }
  }

  function applyBrand(brand) {
    if (!brand) return;
    if (brand.brand_name && brand.brand_name !== "YOUR_BRAND_NAME") {
      document.title = `${brand.brand_name} | تجمیع‌کننده کانفیگ‌های رایگان VPN`;
      document.querySelectorAll("#brand-name, .footer-brand-name").forEach(el => el.textContent = brand.brand_name);
    }
    if (brand.logo) document.getElementById("brand-logo").src = brand.logo;
    if (brand.telegram && brand.telegram !== "YOUR_TELEGRAM_LINK") {
      document.querySelectorAll("#brand-telegram, #footer-telegram").forEach(el => el.href = brand.telegram);
    }
    if (brand.github) {
      document.querySelectorAll("#brand-github, #footer-github").forEach(el => el.href = brand.github);
    }
    if (brand.primary_color && HEX_COLOR_RE.test(brand.primary_color)) {
      document.documentElement.style.setProperty("--accent", brand.primary_color);
    }
  }

  function subscriptionUrl() {
    if (state.brand && state.brand.subscription_url && !state.brand.subscription_url.includes("YOUR_")) {
      return state.brand.subscription_url;
    }
    // fallback: مسیر نسبی روی همان دامنه GitHub Pages
    return new URL("data/sub.txt", window.location.href).toString();
  }

  function renderStats(status) {
    if (!status) return;
    document.getElementById("stat-total").textContent = status.total_configs ?? "–";
    document.getElementById("stat-online").textContent = status.online_configs ?? "–";
    document.getElementById("stat-secure").textContent = status.secure_configs ?? "–";
    document.getElementById("stat-countries").textContent = status.countries ?? "–";
    document.getElementById("stat-sources").textContent = status.active_sources ?? "–";
    document.getElementById("stat-updated").textContent = formatRelativeTime(status.last_update);
  }

  function formatRelativeTime(isoString) {
    if (!isoString) return "–";
    const then = new Date(isoString).getTime();
    if (Number.isNaN(then)) return "–";
    const diffMin = Math.round((Date.now() - then) / 60000);
    if (diffMin < 1) return "لحظاتی پیش";
    if (diffMin < 60) return `${diffMin} دقیقه پیش`;
    const diffH = Math.round(diffMin / 60);
    if (diffH < 24) return `${diffH} ساعت پیش`;
    return `${Math.round(diffH / 24)} روز پیش`;
  }

  function renderProtocolBars(servers) {
    const counts = {};
    servers.forEach(s => { counts[s.protocol] = (counts[s.protocol] || 0) + 1; });
    const max = Math.max(1, ...Object.values(counts));
    const container = document.getElementById("protocol-bars");
    container.innerHTML = "";
    Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .forEach(([protocol, count]) => {
        const row = document.createElement("div");
        row.className = "protocol-bar-row";
        row.innerHTML = `
          <span>${protocol}</span>
          <span class="protocol-bar-track"><span class="protocol-bar-fill" style="width:${(count / max) * 100}%"></span></span>
          <span>${count}</span>`;
        container.appendChild(row);
      });
    if (!Object.keys(counts).length) {
      container.innerHTML = `<p class="muted">هنوز داده‌ای برای نمایش وجود ندارد.</p>`;
    }
  }

  function populateFilterOptions(servers) {
    const protoSelect = document.getElementById("filter-protocol");
    const countrySelect = document.getElementById("filter-country");
    const protocols = [...new Set(servers.map(s => s.protocol))].sort();
    const countries = [...new Set(servers.map(s => s.country_name).filter(Boolean))].sort();

    protocols.forEach(p => {
      const opt = document.createElement("option");
      opt.value = p; opt.textContent = p;
      protoSelect.appendChild(opt);
    });
    countries.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c; opt.textContent = c;
      countrySelect.appendChild(opt);
    });
  }

  function renderServerList(servers) {
    const list = document.getElementById("server-list");
    const empty = document.getElementById("server-empty");
    list.innerHTML = "";

    if (!servers.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;

    const frag = document.createDocumentFragment();
    servers.slice(0, 200).forEach(s => {
      const card = document.createElement("div");
      card.className = "server-card glass";
      const statusClass = s.status === "online" ? "status-online" : "status-offline";
      const secureBadge = s.secure
        ? `<span class="badge badge-secure">TLS/Reality</span>`
        : `<span class="badge badge-insecure">بدون TLS</span>`;
      card.innerHTML = `
        <div class="server-card-top">
          <div>
            <div class="server-name"><span class="status-dot ${statusClass}"></span>${escapeHTML(s.name || s.address)}</div>
            <div class="server-proto">${escapeHTML(s.protocol)}</div>
          </div>
          ${secureBadge}
        </div>
        <div class="server-meta">
          <span>🌍 ${escapeHTML(s.country_name || "Unknown")}</span>
          <span>⚡ ${s.latency ? s.latency + "ms" : "—"}</span>
          <span>🔌 ${escapeHTML(s.transport || "tcp")}</span>
          <span>📡 ${escapeHTML(s.source_name || "")}</span>
        </div>
        <div class="server-actions">
          <button class="btn btn-outline btn-sm" data-copy="${encodeURIComponent(s.raw || "")}">کپی کانفیگ</button>
        </div>`;
      frag.appendChild(card);
    });
    list.appendChild(frag);

    list.querySelectorAll("[data-copy]").forEach(btn => {
      btn.addEventListener("click", () => {
        const raw = decodeURIComponent(btn.getAttribute("data-copy"));
        copyToClipboard(raw, "کانفیگ کپی شد");
      });
    });
  }

  function escapeHTML(str) {
    return String(str ?? "").replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[m]));
  }

  function applyFilters() {
    const q = document.getElementById("search-input").value.trim().toLowerCase();
    const protocol = document.getElementById("filter-protocol").value;
    const country = document.getElementById("filter-country").value;
    const security = document.getElementById("filter-security").value;
    const sortBy = document.getElementById("sort-by").value;

    let result = state.servers.filter(s => {
      if (q && !(`${s.name} ${s.address}`.toLowerCase().includes(q))) return false;
      if (protocol && s.protocol !== protocol) return false;
      if (country && s.country_name !== country) return false;
      if (security === "secure" && !s.secure) return false;
      if (security === "insecure" && s.secure) return false;
      return true;
    });

    result.sort((a, b) => {
      if (sortBy === "latency") return (a.latency ?? Infinity) - (b.latency ?? Infinity);
      if (sortBy === "country") return (a.country_name || "").localeCompare(b.country_name || "");
      if (sortBy === "name") return (a.name || "").localeCompare(b.name || "");
      return 0;
    });

    state.filtered = result;
    renderServerList(result);
  }

  function copyToClipboard(text, message) {
    navigator.clipboard.writeText(text).then(
      () => showToast(message || "کپی شد"),
      () => showToast("کپی ناموفق بود")
    );
  }

  let toastTimer = null;
  function showToast(message) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, 2200);
  }

  function setupDeepLinks() {
    const subUrl = subscriptionUrl();
    const encoded = encodeURIComponent(subUrl);

    document.getElementById("copy-sub-btn").addEventListener("click", () => {
      copyToClipboard(subUrl, "لینک Subscription کپی شد");
    });

    // فقط از Deep Link های شناخته‌شده و مستند استفاده می‌شود
    document.getElementById("import-v2rayng").addEventListener("click", () => {
      window.location.href = `v2rayng://install-config?url=${encoded}`;
    });
    document.getElementById("import-hiddify").addEventListener("click", () => {
      window.location.href = `hiddify://import/${encoded}`;
    });
    document.getElementById("import-nekobox").addEventListener("click", () => {
      // NekoBox فرمت Deep Link رسمی مستندشده‌ی یکسانی ندارد؛ به‌صورت پیش‌فرض کپی می‌کنیم
      copyToClipboard(subUrl, "لینک کپی شد — در NekoBox، Import from Clipboard را بزنید");
    });
  }

  function setupQRModal() {
    const modal = document.getElementById("qr-modal");
    const container = document.getElementById("qr-code-container");

    document.getElementById("show-qr-btn").addEventListener("click", () => {
      container.innerHTML = "";
      // eslint-disable-next-line no-undef
      new QRCode(container, {
        text: subscriptionUrl(),
        width: 220,
        height: 220,
      });
      modal.hidden = false;
    });

    document.getElementById("qr-close").addEventListener("click", () => { modal.hidden = true; });
    modal.addEventListener("click", (e) => { if (e.target === modal) modal.hidden = true; });

    document.getElementById("qr-download").addEventListener("click", () => {
      const canvas = container.querySelector("canvas");
      if (!canvas) return;
      const link = document.createElement("a");
      link.download = "subscription-qr.png";
      link.href = canvas.toDataURL("image/png");
      link.click();
    });
  }

  function setupFilterListeners() {
    ["search-input", "filter-protocol", "filter-country", "filter-security", "sort-by"].forEach(id => {
      document.getElementById(id).addEventListener("input", applyFilters);
      document.getElementById(id).addEventListener("change", applyFilters);
    });
    document.getElementById("refresh-btn").addEventListener("click", () => location.reload());
  }

  async function init() {
    document.getElementById("footer-year").textContent = new Date().getFullYear();

    const [brand, status, servers] = await Promise.all([
      fetchJSON("data/brand.json", null),
      fetchJSON("data/status.json", null),
      fetchJSON("data/servers.json", []),
    ]);

    state.brand = brand;
    state.status = status;
    state.servers = Array.isArray(servers) ? servers : [];

    applyBrand(brand);
    renderStats(status);
    renderProtocolBars(state.servers);
    populateFilterOptions(state.servers);
    renderServerList(state.servers);

    setupFilterListeners();
    setupDeepLinks();
    setupQRModal();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
