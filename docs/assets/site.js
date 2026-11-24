// Shared behaviour for docs/index.html and docs/utility.html.
// Edit SITE_CONFIG to change outbound links. Leave workbenchUrl empty until the
// Streamlit Workbench is actually hosted: the button then points to the local run steps.
const SITE_CONFIG = {
  githubUrl: "https://github.com/Beingstoic1/fintech-compliance-mcp",
  workbenchUrl: "",
  linkedinUrl: "https://www.linkedin.com/in/shubham112/",
  email: "shubham987g@gmail.com",
  emailSubject: "Fintech Compliance MCP",
};

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-link='github']").forEach((el) => { el.href = SITE_CONFIG.githubUrl; });
  document.querySelectorAll("[data-link='linkedin']").forEach((el) => { el.href = SITE_CONFIG.linkedinUrl; });
  document.querySelectorAll("[data-link='email']").forEach((el) => {
    el.href = `mailto:${SITE_CONFIG.email}?subject=${encodeURIComponent(SITE_CONFIG.emailSubject)}`;
  });
  document.querySelectorAll("[data-link='workbench']").forEach((el) => {
    if (SITE_CONFIG.workbenchUrl) {
      el.href = SITE_CONFIG.workbenchUrl;
      el.target = "_blank";
      el.rel = "noopener noreferrer";
    } else {
      el.href = el.dataset.fallback || "index.html#run-locally";
      el.removeAttribute("target");
    }
  });

  const btn = document.querySelector(".menu-btn");
  const nav = document.getElementById("site-nav");
  if (btn && nav) {
    const close = () => { nav.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); };
    btn.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", (e) => { if (e.target.closest("a")) close(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && nav.classList.contains("open")) { close(); btn.focus(); }
    });
  }
});

// Minimal JSON highlighter for static payloads (input is escaped first).
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function highlight(text, lang) {
  const safe = escapeHtml(text);
  if (lang === "json") {
    return safe
      .replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, '<span class="k">$1</span>$2')
      .replace(/(:\s*|\[\s*|,\s*)("(?:[^"\\]|\\.)*")/g, '$1<span class="s">$2</span>')
      .replace(/(:\s*)(-?\d+(?:\.\d+)?|true|false|null)\b/g, '$1<span class="n">$2</span>')
      .replace(/^(\s*\/\/.*)$/gm, '<span class="c">$1</span>');
  }
  // http / sql / shell: dim comment lines, keep the rest plain
  return safe.split("\n").map((line) => (/^\s*(--|#|\/\/)/.test(line) ? `<span class="c">${line}</span>` : line)).join("\n");
}
