// Theme toggle
(function () {
  const KEY = "waf-theme";
  const root = document.documentElement;
  const saved = localStorage.getItem(KEY);
  if (saved) root.setAttribute("data-theme", saved);

  function current() {
    return root.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  function paint(btn) {
    btn.textContent = current() === "dark" ? "☀️ Light" : "🌙 Dark";
  }
  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("theme-toggle");
    if (!btn) return;
    paint(btn);
    btn.addEventListener("click", () => {
      const next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
      paint(btn);
    });
  });
})();

// Reveal-on-scroll
document.addEventListener("DOMContentLoaded", () => {
  const els = document.querySelectorAll(".reveal");
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    });
  }, { threshold: 0.12 });
  els.forEach((el) => io.observe(el));

  // Animated stat counters
  const stats = document.querySelectorAll(".stat .num[data-target]");
  const statIO = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      const target = parseFloat(el.dataset.target);
      const suffix = el.dataset.suffix || "";
      const decimals = el.dataset.decimals ? parseInt(el.dataset.decimals, 10) : 0;
      const duration = 1100;
      const start = performance.now();
      function tick(now) {
        const p = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = (target * eased).toFixed(decimals) + suffix;
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
      statIO.unobserve(el);
    });
  }, { threshold: 0.4 });
  stats.forEach((el) => statIO.observe(el));

  // Chart tabs
  const tabs = document.querySelectorAll(".chart-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.chart;
      document.querySelectorAll(".chart-tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".chart-panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(target).classList.add("active");
    });
  });
});
