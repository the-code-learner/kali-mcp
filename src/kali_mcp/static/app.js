(function () {
  "use strict";

  const status = document.getElementById("status");
  const updates = document.getElementById("updates");
  const updateGuidance = document.getElementById("update-guidance");
  const installButton = document.getElementById("install-update");
  const jobs = document.getElementById("jobs");
  const audit = document.getElementById("audit");
  if (!status) return;

  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);

  async function refresh() {
    try {
      const response = await fetch("/api/v1/status", {
        credentials: "same-origin",
        cache: "no-store"
      });
      if (!response.ok) throw new Error("Status unavailable; sign in again if needed");
      const data = await response.json();
      status.textContent = "Broker: " + data.broker + " • Jobs: " + data.jobs.length;

      const release = data.updates || {};
      const installed = release.installed || "unknown";
      const latest = release.latest || "not checked";
      let outcome = "Checking GitHub ...";
      if (release.error) outcome = "GitHub check failed: " + release.error;
      else if (release.update_available === true) outcome = "New release available";
      else if (release.update_available === false) outcome = "Up to date";
      else if (release.checked) outcome = "Latest checked; installed version not verified";

      updates.textContent = "Installed: " + installed +
        " • Latest available (" + (release.channel || "unknown") + "): " + latest +
        " • " + outcome;
      if (updateGuidance && typeof release.install_guidance === "string") {
        updateGuidance.textContent = release.install_guidance;
      }
      if (installButton) installButton.disabled = release.install_allowed !== true;

      jobs.innerHTML = data.jobs.map(job =>
        "<tr><td>" + esc(job.tool_id) + "</td><td>" +
        esc(job.actor) + "</td><td>" + esc(job.state) +
        "</td><td><a href=\"/jobs/" + encodeURIComponent(job.id) + "\">" +
        esc(job.id.slice(0, 12)) + "</a></td></tr>"
      ).join("");
      audit.textContent = data.audit.map(item =>
        item.at + " " + item.actor + " " + item.action + " " + item.decision
      ).join("\n");
    } catch (error) {
      status.textContent = error.message;
      if (updates) updates.textContent = "Version status unavailable — retry after Core restarts.";
    }
  }

  refresh();
  setInterval(refresh, 3000);
})();
