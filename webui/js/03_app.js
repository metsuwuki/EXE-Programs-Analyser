function bind() {
      document.querySelectorAll(NAV_VIEW_SELECTOR).forEach(btn => btn.addEventListener("click", () => switchView(btn.dataset.view)));
      const supportBtn = document.getElementById("btnSupport");
      if (supportBtn) {
        supportBtn.addEventListener("click", (e) => {
          if (window.ipc && typeof window.ipc.postMessage === "function") {
            e.preventDefault();
            post("open_path", { path: supportBtn.href }).catch(err => addLog("[error] " + err.message));
          }
        });
      }
      document.getElementById("btnPickTarget").addEventListener("click", async () => {
        try {
          const payload = await post("pick_target", {});
          if (payload && payload.path) {
            document.getElementById("targetPath").value = payload.path;
            await refreshTargetType(payload.path);
          }
        } catch (e) {
          addLog("[error] " + e.message);
        }
      });
      document.getElementById("targetPath").addEventListener("change", (e) => {
        refreshTargetType(e.target.value).catch(() => {});
      });
      document.getElementById("btnRun").addEventListener("click", () => runAnalysis().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnStop").addEventListener("click", () => stopAnalysis().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnRefreshReports").addEventListener("click", () => listReports().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnListReports").addEventListener("click", () => listReports().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnOpenReportsDir").addEventListener("click", () => post("open_path", { path: document.getElementById("outDirInput").value || "logs" }).catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnOpenFullLog").addEventListener("click", () => openReportLog("full").catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnOpenIssuesLog").addEventListener("click", () => openReportLog("issues").catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnExportMd").addEventListener("click", () => exportReport("md").catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnExportHtml").addEventListener("click", () => exportReport("html").catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnSaveSettings").addEventListener("click", () => saveUiSettings().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnCreateBundle").addEventListener("click", () => createBundle().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnRerunScenario").addEventListener("click", () => rerunScenario().catch(e => addLog("[error] " + e.message)));
      document.getElementById("btnCloseReport").addEventListener("click", clearCurrentReport);
      document.getElementById("powerProfileSelect").addEventListener("change", (e) => {
        applyPowerProfilePreset(e.target.value);
      });
      document.getElementById("findingSearch").addEventListener("input", renderFindings);
      document.getElementById("severityFilter").addEventListener("change", renderFindings);
      document.getElementById("groupFilter").addEventListener("change", renderFindings);
      document.getElementById("langSelect").addEventListener("change", (e) => {
        previewLanguageChange(e.target.value);
      });
      document.getElementById("accentSelect").addEventListener("change", (e) => {
        previewThemeChange(e.target.value);
      });
      document.getElementById("themeModeSelect").addEventListener("change", (e) => {
        previewThemeModeChange(e.target.value);
      });

      systemThemeMedia.addEventListener("change", () => {
        if (state.themeMode === "AUTO") {
          applyThemeMode("AUTO");
        }
      });

      window.addEventListener("resize", () => {
        if (state.report) applyMetrics(state.report);
        const active = document.querySelector(".nav-btn.active");
        if (active) {
          document.getElementById("sidebar").style.setProperty("--nav-y", `${active.offsetTop}px`);
        }
      });
    }

    async function bootstrap() {
      enhanceSelects();
      initHeroParticles();
      bind();
      await loadSettings();
      await listReports();
      switchView("home");
      addLog("[ui] web frontend ready");
      drawSeverityDonut({ pass: 0, warn: 0, fail: 0 });
      drawRuntimeChart({ durations: [], p50: 0, p95: 0 });
      document.getElementById("appRoot").classList.add("ready");
      const splash = document.getElementById("splash");
      splash.classList.add("hide");
      setTimeout(() => splash.remove(), 420);
    }

    bootstrap().catch(err => {
      document.getElementById("appRoot").classList.add("ready");
      const splash = document.getElementById("splash");
      if (splash) {
        splash.classList.add("hide");
        setTimeout(() => splash.remove(), 420);
      }
      document.getElementById("liveLog").textContent = "Bootstrap failed: " + err.message;
    });
