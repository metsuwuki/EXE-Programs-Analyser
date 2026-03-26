const state = {
      lang: "en",
      accent: "AMETHYST",
      themeMode: "AUTO",
      settings: null,
      report: null,
      reportPath: null,
      reports: [],
      logs: [],
      selectedScenario: null,
      pending: new Map(),
      view: "home",
      runStart: 0,
      progressTick: null
    };

    const NAV_VIEW_SELECTOR = ".nav-btn[data-view]";
    const ACCENT_OPTIONS = ["AMETHYST", "CHERRY", "LAVA", "GOLD", "EMERALD", "SEA", "SAPPHIRE", "QUARTZ", "ASH"];
    const LEGACY_ACCENT_MAP = {
      LIME: "EMERALD",
      CYAN: "SEA",
      CRIMSON: "CHERRY"
    };
    const THEME_MODE_OPTIONS = ["AUTO", "DARK", "LIGHT"];
    const POWER_PROFILE_OPTIONS = ["BASIC", "AUDIT", "PENTEST", "EXTREME"];
    const SANDBOX_PROFILE_OPTIONS = ["limited", "isolated", "none"];
    const VERDICT_MODE_OPTIONS = ["BALANCED", "STRICT"];
    const systemThemeMedia = window.matchMedia("(prefers-color-scheme: light)");

    function tr(key) {
      const map = t[state.lang] || t.en;
      return map[key] || t.en[key] || key;
    }

    function setText(id, key) {
      const el = document.getElementById(id);
      if (el) el.textContent = tr(key);
    }

    function setPlaceholder(id, key) {
      const el = document.getElementById(id);
      if (el) el.setAttribute("placeholder", tr(key));
    }

    function viewKey(view) {
      const map = {
        home: "viewHome",
        reports: "viewReports",
        runtime: "viewRuntime",
        settings: "viewSettings"
      };
      return map[view] || "viewHome";
    }

    function accentLabel(value) {
      const map = {
        CHERRY: "accentCherry",
        LAVA: "accentLava",
        GOLD: "accentGold",
        EMERALD: "accentEmerald",
        SEA: "accentSea",
        SAPPHIRE: "accentSapphire",
        AMETHYST: "accentAmethyst",
        QUARTZ: "accentQuartz",
        ASH: "accentAsh"
      };
      const key = map[normalizeAccent(value)] || "accentAmethyst";
      return tr(key);
    }

    function localizeToolStatus(value) {
      const v = String(value || "").toLowerCase();
      if (!v) return tr("unknown");
      if (v === "configured") return tr("configured");
      if (v === "not configured") return tr("notConfigured");
      if (v === "unknown") return tr("unknown");
      return value;
    }

    function pickLang(raw) {
      const v = (raw || "").toLowerCase();
      if (v === "ru" || v === "uk" || v === "de" || v === "en") return v;
      const n = (navigator.language || "en").toLowerCase();
      if (n.startsWith("ru")) return "ru";
      if (n.startsWith("uk")) return "uk";
      if (n.startsWith("de")) return "de";
      return "en";
    }

    function normalizeAccent(accent) {
      const raw = String(accent || "AMETHYST").toUpperCase();
      const mapped = LEGACY_ACCENT_MAP[raw] || raw;
      return ACCENT_OPTIONS.includes(mapped) ? mapped : "AMETHYST";
    }

    function normalizeThemeMode(mode) {
      const raw = String(mode || "AUTO").toUpperCase();
      return THEME_MODE_OPTIONS.includes(raw) ? raw : "AUTO";
    }

    function normalizePowerProfile(value) {
      const raw = String(value || "BASIC").toUpperCase();
      return POWER_PROFILE_OPTIONS.includes(raw) ? raw : "BASIC";
    }

    function normalizeSandboxProfile(value) {
      const raw = String(value || "limited").toLowerCase();
      return SANDBOX_PROFILE_OPTIONS.includes(raw) ? raw : "limited";
    }

    function normalizeVerdictMode(value) {
      const raw = String(value || "BALANCED").toUpperCase();
      return VERDICT_MODE_OPTIONS.includes(raw) ? raw : "BALANCED";
    }

    function resolvedThemeMode(mode) {
      const normalized = normalizeThemeMode(mode);
      if (normalized === "AUTO") {
        return systemThemeMedia.matches ? "LIGHT" : "DARK";
      }
      return normalized;
    }

    function applyAccent(accent) {
      const next = normalizeAccent(accent);
      const root = document.documentElement;
      const prev = root.getAttribute("data-accent") || "AMETHYST";
      root.setAttribute("data-accent", next);
      document.getElementById("themeBadge").textContent = tr("lblAccent").toUpperCase() + ": " + accentLabel(next);
      state.accent = next;

      if (prev !== next) {
        root.classList.add("accent-morph");
        setTimeout(() => root.classList.remove("accent-morph"), 210);
        if (state.report) {
          const m = computeMetrics(state.report);
          drawRuntimeChart(m);
        }
      }
    }

    function applyThemeMode(mode) {
      const normalized = normalizeThemeMode(mode);
      const resolved = resolvedThemeMode(normalized);
      const root = document.documentElement;
      root.setAttribute("data-theme", resolved);
      state.themeMode = normalized;
      const modeSelect = document.getElementById("themeModeSelect");
      if (modeSelect && modeSelect.value !== normalized) {
        modeSelect.value = normalized;
      }
      syncEnhancedSelects();
    }

    function applyTexts() {
      setText("navHome", "navHome");
      setText("navReports", "navReports");
      setText("navRuntime", "navRuntime");
      setText("navSettings", "navSettings");
      setText("navSupport", "navSupport");
      setText("titleMain", "topTitle");
      setText("titleSub", "topSub");
      setText("heroLabel", "heroLabel");
      setText("heroTitleLead", "heroTitleLead");
      setText("heroTitleAccent", "heroTitleAccent");
      setText("heroSub", "heroSub");
      setText("heroTagFindings", "heroTagFindings");
      setText("heroTagRuntime", "heroTagRuntime");
      setText("heroTagDiagnostics", "heroTagDiagnostics");
      setText("heroStatParticles", "heroStatParticles");
      setText("heroStatRender", "heroStatRender");
      setText("heroStatAccents", "heroStatAccents");
      setText("heroStatTransitions", "heroStatTransitions");
      setText("lblTarget", "lblTarget");
      setText("targetHelp", "targetHelp");
      setText("btnPickTarget", "btnPickTarget");
      setText("lblMode", "lblMode");
      setText("lblVerdictMode", "lblVerdictMode");
      setText("lblPowerProfile", "lblPowerProfile");
      setText("lblSandboxProfile", "lblSandboxProfile");
      setText("lblRuns", "lblRuns");
      setText("lblTimeout", "lblTimeout");
      setText("lblOutDir", "lblOutDir");
      setText("btnRun", "btnRun");
      setText("btnStop", "btnStop");
      setText("btnRefreshReports", "btnRefreshReports");
      setText("kpiStatusLabel", "kpiStatusLabel");
      setText("kpiScoreLabel", "kpiScoreLabel");
      setText("kpiWarnLabel", "kpiWarnLabel");
      setText("kpiFailLabel", "kpiFailLabel");
      setText("kpiP50Label", "kpiP50Label");
      setText("kpiP95Label", "kpiP95Label");
      document.getElementById("kpiP50Label").title = tr("p50Title");
      document.getElementById("kpiP95Label").title = tr("p95Title");
      setText("latencyHint", "latencyHint");
      setText("infoPassName", "infoPassName");
      setText("infoWarnName", "infoWarnName");
      setText("infoFailName", "infoFailName");
      setText("infoStabilityName", "infoStabilityName");
      setText("vizSeverityTitle", "vizSeverityTitle");
      setText("vizRuntimeTitle", "vizRuntimeTitle");
      setText("btnListReports", "btnListReports");
      setText("btnOpenReportsDir", "btnOpenReportsDir");
      setText("btnOpenFullLog", "btnOpenFullLog");
      setText("btnOpenIssuesLog", "btnOpenIssuesLog");
      setText("btnExportMd", "btnExportMd");
      setText("btnExportHtml", "btnExportHtml");
      setText("thReportsModified", "thReportsModified");
      setText("thReportsSize", "thReportsSize");
      setText("thReportsPath", "thReportsPath");
      setText("thReportsAction", "thReportsAction");
      setText("btnCloseReport", "btnCloseReport");
      setText("lblSearch", "lblSearch");
      setPlaceholder("findingSearch", "findingSearchPlaceholder");
      setText("lblSeverity", "lblSeverity");
      setText("lblGroup", "lblGroup");
      const group = document.getElementById("groupFilter");
      if (group && group.options.length >= 3) {
        group.options[0].textContent = tr("groupNone");
        group.options[1].textContent = tr("groupSeverity");
        group.options[2].textContent = tr("groupCategory");
      }
      setText("thFindingsSeverity", "thFindingsSeverity");
      setText("thFindingsCode", "thFindingsCode");
      setText("thFindingsCategory", "thFindingsCategory");
      setText("thFindingsPoints", "thFindingsPoints");
      setText("thFindingsMessage", "thFindingsMessage");
      setText("runtimeHint", "runtimeHint");
      setText("thRuntimeScenario", "thRuntimeScenario");
      setText("thRuntimeExit", "thRuntimeExit");
      setText("thRuntimeTimeout", "thRuntimeTimeout");
      setText("thRuntimeDuration", "thRuntimeDuration");
      setText("thRuntimeStdout", "thRuntimeStdout");
      setText("thRuntimeStderr", "thRuntimeStderr");
      setText("lblLanguage", "lblLanguage");
      setText("lblAccent", "lblAccent");
      setText("lblThemeMode", "lblThemeMode");
      setText("lblDefaultMode", "lblDefaultMode");
      setText("lblDefaultPowerProfile", "lblDefaultPowerProfile");
      setText("lblDefaultSandboxProfile", "lblDefaultSandboxProfile");
      setText("lblReportsDir", "lblReportsDir");
      setText("lblAnalyzerPath", "lblAnalyzerPath");
      setText("btnSaveSettings", "btnSaveSettings");
      setText("detailsTitle", "detailsTitle");
      setText("dLabelFinalStatus", "dLabelFinalStatus");
      setText("dLabelFindings", "dLabelFindings");
      setText("dLabelRuntimeRows", "dLabelRuntimeRows");
      setText("dLabelFlakiness", "dLabelFlakiness");
      setText("dLabelStability", "dLabelStability");
      setText("dLabelScenario", "dLabelScenario");
      setText("btnCreateBundle", "btnCreateBundle");
      setText("btnRerunScenario", "btnRerunScenario");
      document.getElementById("viewTitle").textContent = tr(viewKey(state.view));
      if (!state.report) {
        document.getElementById("reportHint").textContent = tr("noReport");
      }
      const statusEl = document.getElementById("kStatus");
      const status = statusEl.textContent.trim().toUpperCase();
      if (["IDLE", "��������", "�ײ�������"].includes(status)) statusEl.textContent = tr("statusIdle");
      if (["RUNNING", "� ������", "�����Ӫ����", "LAEUFT"].includes(status)) statusEl.textContent = tr("statusRunning");
      if (["DONE", "������", "FERTIG"].includes(status)) statusEl.textContent = tr("statusDone");
      const mode = document.getElementById("modeSelect").value || "MIN";
      document.getElementById("modeBadge").textContent = tr("lblMode").toUpperCase() + ": " + mode;
      document.getElementById("themeBadge").textContent = tr("lblAccent").toUpperCase() + ": " + accentLabel(state.accent || "AMETHYST");
      document.querySelector(".confirm-check-text").textContent = tr("confirmPentest");
      const targetHint = document.getElementById("targetTypeHint");
      if (targetHint && !targetHint.textContent.trim()) {
        targetHint.textContent = `${tr("targetTypePrefix")} unknown`;
      }

      const langSelect = document.getElementById("langSelect");
      if (langSelect && langSelect.options.length >= 5) {
        langSelect.options[0].textContent = tr("langAuto");
        langSelect.options[1].textContent = "English";
        langSelect.options[2].textContent = "Russian";
        langSelect.options[3].textContent = "Ukrainian";
        langSelect.options[4].textContent = "German";
      }

      const accentSelect = document.getElementById("accentSelect");
      if (accentSelect && accentSelect.options.length >= 9) {
        const accentKeys = {
          CHERRY: "accentCherry",
          LAVA: "accentLava",
          GOLD: "accentGold",
          EMERALD: "accentEmerald",
          SEA: "accentSea",
          SAPPHIRE: "accentSapphire",
          AMETHYST: "accentAmethyst",
          QUARTZ: "accentQuartz",
          ASH: "accentAsh"
        };
        Array.from(accentSelect.options).forEach((opt) => {
          const key = accentKeys[String(opt.value || "").toUpperCase()];
          if (key) opt.textContent = tr(key);
        });
      }

      const themeModeSelect = document.getElementById("themeModeSelect");
      if (themeModeSelect && themeModeSelect.options.length >= 3) {
        themeModeSelect.options[0].textContent = tr("themeModeAuto");
        themeModeSelect.options[1].textContent = tr("themeModeDark");
        themeModeSelect.options[2].textContent = tr("themeModeLight");
      }

      const supportBtn = document.getElementById("btnSupport");
      if (supportBtn) supportBtn.title = tr("navSupport");
      syncEnhancedSelects();
    }

    function initHeroParticles() {
      const c = document.getElementById("heroParticles");
      if (!c) return;
      const ctx = c.getContext("2d");
      const stateP = { dots: [], raf: 0, w: 0, h: 0, dpr: 1 };

      const build = () => {
        const rect = c.getBoundingClientRect();
        stateP.dpr = Math.min(2, window.devicePixelRatio || 1);
        stateP.w = Math.max(320, Math.floor(rect.width));
        stateP.h = Math.max(180, Math.floor(rect.height));
        c.width = Math.floor(stateP.w * stateP.dpr);
        c.height = Math.floor(stateP.h * stateP.dpr);
        const count = Math.max(64, Math.floor((stateP.w * stateP.h) / 4500));
        stateP.dots = Array.from({ length: count }, () => ({
          x: Math.random() * stateP.w,
          y: Math.random() * stateP.h,
          vx: (Math.random() - 0.5) * 0.48,
          vy: (Math.random() - 0.5) * 0.48,
          r: 0.9 + Math.random() * 1.4
        }));
      };

      const tick = () => {
        const accent = cssVar("--accent", "#ff6b2e");
        const accent2 = cssVar("--accent-2", "#ff9d2e");
        ctx.setTransform(stateP.dpr, 0, 0, stateP.dpr, 0, 0);
        ctx.clearRect(0, 0, stateP.w, stateP.h);

        for (let i = 0; i < stateP.dots.length; i++) {
          const a = stateP.dots[i];
          a.x += a.vx;
          a.y += a.vy;
          if (a.x < -10 || a.x > stateP.w + 10) a.vx *= -1;
          if (a.y < -10 || a.y > stateP.h + 10) a.vy *= -1;

          for (let j = i + 1; j < stateP.dots.length; j++) {
            const b = stateP.dots[j];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const dist = Math.hypot(dx, dy);
            if (dist > 120) continue;
            ctx.globalAlpha = (1 - dist / 120) * 0.32;
            ctx.strokeStyle = i % 2 === 0 ? accent : accent2;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }

        ctx.globalAlpha = 0.82;
        for (const p of stateP.dots) {
          ctx.fillStyle = Math.random() > 0.5 ? accent : accent2;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
        stateP.raf = requestAnimationFrame(tick);
      };

      build();
      if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        stateP.raf = requestAnimationFrame(tick);
      }
      window.addEventListener("resize", () => {
        cancelAnimationFrame(stateP.raf);
        build();
        if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
          stateP.raf = requestAnimationFrame(tick);
        }
      });
    }

    function syncEnhancedSelects() {
      document.querySelectorAll("select[data-ux-enhanced='1']").forEach((select) => {
        if (typeof select.__uxSync === "function") select.__uxSync();
      });
    }

    function showSelectDialog(select, titleText) {
      const old = document.getElementById("selectDialog");
      if (old) old.remove();
      const isAccentPicker = select.id === "accentSelect";
      const accentPreview = {
        CHERRY: "linear-gradient(120deg, #d53a47, #f06a7a)",
        LAVA: "linear-gradient(120deg, #ff6b2e, #ff9d2e)",
        GOLD: "linear-gradient(120deg, #d6a83d, #f0cb73)",
        EMERALD: "linear-gradient(120deg, #2db873, #49d68d)",
        SEA: "linear-gradient(120deg, #29bfb0, #63e5d8)",
        SAPPHIRE: "linear-gradient(120deg, #2f74de, #58a1ff)",
        AMETHYST: "linear-gradient(120deg, #8f4dff, #c96eff)",
        QUARTZ: "linear-gradient(120deg, #d16eb3, #f38bcf)",
        SNOW: "linear-gradient(120deg, #dbe6f4, #f7fbff)",
        ASH: "linear-gradient(120deg, #8f97a4, #bdc5d2)"
      };

      const optionLabel = (opt) => {
        const label = String((opt && (opt.label || opt.textContent)) || "").trim();
        if (label) return label;
        const fallback = String((opt && opt.value) || "").trim();
        return fallback || "-";
      };

      const options = Array.from(select.options).filter((opt) => !opt.disabled);
      let pendingValue = select.value;

      const wrap = document.createElement("div");
      wrap.id = "selectDialog";
      wrap.className = "picker-backdrop";
      wrap.innerHTML = `
        <div class="picker-dialog" role="dialog" aria-modal="true" aria-label="${tr("pickerTitle")}">
          <div class="picker-head">
            <div>
              <div class="picker-title">${titleText || tr("pickerTitle")}</div>
              <div class="picker-sub">${tr("pickerSub")}</div>
            </div>
          </div>
          <div class="picker-body">
            <div class="picker-list" id="pickerList"></div>
            <div class="picker-side">
              <div>
                <div class="picker-k">${tr("pickerCurrent")}</div>
                <div class="picker-v" id="pickerCurrent">-</div>
              </div>
              <div>
                <div class="picker-k">${tr("pickerPending")}</div>
                <div class="picker-v" id="pickerPending">-</div>
              </div>
              <div id="pickerPreviewWrap" class="${isAccentPicker ? "" : "hidden"}">
                <div class="picker-k">Preview</div>
                <div class="picker-preview" id="pickerPreview"></div>
              </div>
            </div>
          </div>
          <div class="picker-foot">
            <button class="btn" id="pickerCancel" type="button">${tr("pickerCancel")}</button>
            <button class="btn primary" id="pickerApply" type="button">${tr("pickerApply")}</button>
          </div>
        </div>
      `;
      document.body.appendChild(wrap);

      const list = document.getElementById("pickerList");
      const currentBox = document.getElementById("pickerCurrent");
      const pendingBox = document.getElementById("pickerPending");
      const previewBox = document.getElementById("pickerPreview");

      const selectedLabel = () => {
        const selected = options.find((opt) => opt.value === pendingValue);
        return selected ? optionLabel(selected) : "-";
      };

      currentBox.textContent = optionLabel(select.options[select.selectedIndex]);
      pendingBox.textContent = selectedLabel();
      if (isAccentPicker && previewBox) {
        previewBox.style.background = accentPreview[pendingValue] || accentPreview.AMETHYST;
      }

      const render = () => {
        list.innerHTML = "";
        options.forEach((opt) => {
          const item = document.createElement("button");
          item.type = "button";
          item.className = "picker-item" + (opt.value === pendingValue ? " is-active" : "");
          if (isAccentPicker) {
            const swatch = accentPreview[opt.value] || accentPreview.AMETHYST;
            item.innerHTML = `<span class="picker-item-row"><span>${optionLabel(opt)}</span><span class="picker-swatch" style="background:${swatch}"></span></span>`;
          } else {
            item.textContent = optionLabel(opt);
          }
          item.addEventListener("click", () => {
            pendingValue = opt.value;
            pendingBox.textContent = selectedLabel();
            if (isAccentPicker && previewBox) {
              previewBox.style.background = accentPreview[pendingValue] || accentPreview.AMETHYST;
            }
            render();
          });
          item.addEventListener("dblclick", () => {
            pendingValue = opt.value;
            applyAndClose();
          });
          list.appendChild(item);
        });
      };

      const close = () => {
        document.removeEventListener("keydown", onKey);
        if (wrap && wrap.parentNode) wrap.remove();
      };

      const applyAndClose = () => {
        if (select.value !== pendingValue) {
          select.value = pendingValue;
          select.dispatchEvent(new Event("change", { bubbles: true }));
        }
        if (typeof select.__uxSync === "function") select.__uxSync();
        close();
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          close();
          return;
        }
        if (e.key === "Enter") {
          applyAndClose();
        }
      };

      wrap.addEventListener("click", (e) => {
        if (e.target === wrap) close();
      });

      document.getElementById("pickerCancel").addEventListener("click", close);
      document.getElementById("pickerApply").addEventListener("click", applyAndClose);
      document.addEventListener("keydown", onKey);
      render();
    }

    function showApplyPopup(kind, label, onApply, onCancel) {
      const old = document.getElementById("applyPopup");
      if (old) old.remove();

      const pop = document.createElement("div");
      pop.id = "applyPopup";
      pop.className = "apply-pop";
      pop.innerHTML = `<div class="apply-pop-title">Preview</div><div class="apply-pop-text">Selected ${label}. Apply now?</div><div class="apply-pop-row"><button class="btn" id="applyCancel">Cancel</button><button class="btn primary" id="applyOk">Apply</button></div>`;
      document.body.appendChild(pop);

      const close = () => {
        if (pop && pop.parentNode) pop.remove();
      };

      document.getElementById("applyCancel").addEventListener("click", () => {
        close();
        onCancel();
      });
      document.getElementById("applyOk").addEventListener("click", () => {
        close();
        onApply();
      });

      setTimeout(() => {
        if (document.getElementById("applyPopup")) {
          close();
          onCancel();
        }
      }, 5200);
    }

    function previewThemeChange(nextTheme) {
      const select = document.getElementById("accentSelect");
      const previous = state.settings && state.settings.accent ? normalizeAccent(state.settings.accent) : state.accent || "AMETHYST";
      const next = normalizeAccent(nextTheme || "AMETHYST");
      if (next === String(previous).toUpperCase()) return;

      applyAccent(next);
      if (!state.settings) state.settings = {};
      state.settings.accent = next;
      select.value = next;
      syncEnhancedSelects();
      flashNote(tr("accentApplied"));
    }

    function previewThemeModeChange(nextMode) {
      const select = document.getElementById("themeModeSelect");
      const previous = state.settings && state.settings.theme ? normalizeThemeMode(state.settings.theme) : state.themeMode;
      const next = normalizeThemeMode(nextMode || "AUTO");
      if (next === previous) return;

      applyThemeMode(next);
      if (!state.settings) state.settings = {};
      state.settings.theme = next;
      select.value = next;
      syncEnhancedSelects();
    }

    function previewLanguageChange(nextLangRaw) {
      const select = document.getElementById("langSelect");
      const previous = state.settings && state.settings.language ? String(state.settings.language).toLowerCase() : "auto";
      const nextRaw = String(nextLangRaw || "auto").toLowerCase();
      if (nextRaw === previous) return;

      state.lang = nextRaw === "auto" ? pickLang("") : pickLang(nextRaw);
      applyTexts();
      if (state.report) {
        renderFindings();
        renderRuntime();
      }
      if (state.reports.length) {
        listReports().catch(e => addLog("[error] " + e.message));
      }
      if (!state.settings) state.settings = {};
      state.settings.language = nextRaw;
      select.value = nextRaw;
      syncEnhancedSelects();
      flashNote(tr("languageApplied"));
    }

    function applyPowerProfilePreset(profileRaw) {
      const profile = normalizePowerProfile(profileRaw);
      const modeEl = document.getElementById("modeSelect");
      const verdictEl = document.getElementById("verdictModeSelect");
      const runsEl = document.getElementById("runsInput");
      const timeoutEl = document.getElementById("timeoutInput");
      const sandboxEl = document.getElementById("sandboxProfileSelect");
      const confirmEl = document.getElementById("confirmPentest");

      if (profile === "BASIC") {
        modeEl.value = "MIN";
        verdictEl.value = "BALANCED";
        runsEl.value = "4";
        timeoutEl.value = "4";
        sandboxEl.value = "limited";
        confirmEl.checked = false;
      } else if (profile === "AUDIT") {
        modeEl.value = "MIN";
        verdictEl.value = "BALANCED";
        runsEl.value = "8";
        timeoutEl.value = "5";
        sandboxEl.value = "limited";
        confirmEl.checked = false;
      } else if (profile === "PENTEST") {
        modeEl.value = "PENTEST";
        verdictEl.value = "STRICT";
        runsEl.value = "10";
        timeoutEl.value = "6";
        sandboxEl.value = "isolated";
      } else {
        modeEl.value = "PENTEST";
        verdictEl.value = "STRICT";
        runsEl.value = "12";
        timeoutEl.value = "8";
        sandboxEl.value = "isolated";
      }

      document.getElementById("modeBadge").textContent = tr("lblMode").toUpperCase() + ": " + modeEl.value;
      document.getElementById("stMode").textContent = "mode=" + modeEl.value;
      document.getElementById("stSandbox").textContent = "sandbox=" + sandboxEl.value;
      syncEnhancedSelects();
    }

    function enhanceSelects() {
      const optionLabel = (opt) => {
        const label = String((opt && (opt.label || opt.textContent)) || "").trim();
        if (label) return label;
        const fallback = String((opt && opt.value) || "").trim();
        return fallback || "-";
      };

      document.querySelectorAll("select").forEach((select) => {
        if (select.dataset.uxEnhanced === "1") return;
        select.dataset.uxEnhanced = "1";
        select.classList.add("ux-native");

        const shell = document.createElement("div");
        shell.className = "select-shell";
        select.parentNode.insertBefore(shell, select);
        shell.appendChild(select);

        const trigger = document.createElement("button");
        trigger.type = "button";
        trigger.className = "select-trigger";
        shell.appendChild(trigger);

        const syncFromNative = () => {
          const current = select.options[select.selectedIndex];
          trigger.textContent = current ? optionLabel(current) : "-";
        };

        syncFromNative();
        select.__uxSync = syncFromNative;

        trigger.addEventListener("click", (e) => {
          e.stopPropagation();
          const field = shell.closest(".field");
          const title = field ? field.querySelector("label") : null;
          showSelectDialog(select, title ? title.textContent.trim() : tr("pickerTitle"));
        });

        select.addEventListener("change", syncFromNative);
        shell.addEventListener("click", (e) => e.stopPropagation());
      });
    }

    function id() {
      return "r-" + Math.random().toString(16).slice(2);
    }

    function post(cmd, payload = {}) {
      const reqId = id();
      const host = window.ipc && typeof window.ipc.postMessage === "function";
      if (!host) return Promise.reject(new Error("IPC bridge is unavailable"));

      const p = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          state.pending.delete(reqId);
          reject(new Error("IPC timeout"));
        }, 30000);
        state.pending.set(reqId, { resolve, reject, timeout });
      });

      window.ipc.postMessage(JSON.stringify({ id: reqId, cmd, payload }));
      return p;
    }

    function onHostMessage(envelope) {
      if (!envelope || typeof envelope !== "object") return;

      if (envelope.type === "response") {
        const wait = state.pending.get(envelope.id);
        if (!wait) return;
        clearTimeout(wait.timeout);
        state.pending.delete(envelope.id);
        if (envelope.ok) wait.resolve(envelope.payload);
        else wait.reject(new Error(envelope.error || "Unknown host error"));
        return;
      }

      if (envelope.type === "event") {
        if (envelope.event === "analysis-log") addLog(String(envelope.payload || ""));
        if (envelope.event === "analysis-finished") {
          endProgress();
          document.getElementById("stRun").textContent = "analysis=idle";
          document.getElementById("kStatus").textContent = tr("statusDone");
          if (envelope.payload && envelope.payload.reportPath) {
            document.getElementById("reportHint").textContent = envelope.payload.reportPath;
            loadReport(envelope.payload.reportPath);
          }
          listReports();
          flashNote(tr("analysisFinished"));
        }
      }
    }

    window.__METSUKI_HOST_DISPATCH = onHostMessage;

    function flashNote(text) {
      const div = document.createElement("div");
      div.className = "float-note";
      div.textContent = text;
      document.body.appendChild(div);
      setTimeout(() => div.remove(), 1300);
    }

    function addLog(line) {
      if (!line) return;
      state.logs.push(line);
      if (state.logs.length > 1400) state.logs.splice(0, state.logs.length - 1400);
      const live = document.getElementById("liveLog");
      const details = document.getElementById("detailsBox");
      live.textContent = state.logs.join("\n");
      live.scrollTop = live.scrollHeight;
      if (!state.report) {
        details.classList.remove("details-rich");
        details.textContent = state.logs.slice(-120).join("\n");
        details.scrollTop = details.scrollHeight;
      }
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function formatBool(value) {
      return value ? "yes" : "no";
    }

    function formatShortBytes(value) {
      const size = Number(value || 0);
      if (size < 1024) return `${size} B`;
      if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
      return `${(size / (1024 * 1024)).toFixed(2)} MB`;
    }

    function renderDetailChips(items) {
      return `<div class="details-grid">${items.map((item) => `
        <div class="details-chip">
          <div class="details-chip-k">${escapeHtml(item.label)}</div>
          <div class="details-chip-v">${escapeHtml(item.value)}</div>
        </div>
      `).join("")}</div>`;
    }

    function renderScenarioDetails(runtimeRow) {
      if (!runtimeRow) return "";
      const trace = runtimeRow.trace || {};
      const events = Array.isArray(trace.events) ? trace.events : [];
      const previews = [];
      if (trace.stdout_preview) {
        previews.push(`<div class="preview-block"><strong>stdout preview</strong>\n${escapeHtml(trace.stdout_preview)}</div>`);
      }
      if (trace.stderr_preview) {
        previews.push(`<div class="preview-block"><strong>stderr preview</strong>\n${escapeHtml(trace.stderr_preview)}</div>`);
      }

      return `
        <section class="details-section">
          <h4>Selected Scenario</h4>
          ${renderDetailChips([
            { label: "Scenario", value: runtimeRow.scenario || "-" },
            { label: "Exit code", value: runtimeRow.exit_code ?? "null" },
            { label: "Timed out", value: formatBool(runtimeRow.timed_out) },
            { label: "Duration", value: `${runtimeRow.duration_ms || 0} ms` },
            { label: "stdout", value: formatShortBytes(runtimeRow.stdout_len || 0) },
            { label: "stderr", value: formatShortBytes(runtimeRow.stderr_len || 0) },
          ])}
          <div class="preview-block"><strong>Failure reason</strong>\n${escapeHtml(runtimeRow.failure_reason || "-")}</div>
        </section>
        <section class="details-section">
          <h4>Trace Timeline</h4>
          <div class="trace-events">
            ${events.map((event) => `
              <div class="trace-event">
                <div class="trace-head">
                  <span>${escapeHtml(event.stage || "event")}</span>
                  <span>${escapeHtml(`${event.at_ms || 0} ms`)}</span>
                </div>
                <div class="trace-detail">${escapeHtml(event.detail || "-")}</div>
              </div>
            `).join("") || `<div class="trace-event"><div class="trace-detail">No runtime trace events.</div></div>`}
          </div>
          ${previews.join("")}
        </section>
      `;
    }

    function renderReportOverview(report) {
      const summary = report.summary || {};
      const severity = summary.severity || {};
      const runtimeSummary = summary.runtime || {};
      const artifacts = report.artifacts || {};
      const staticAnalysis = artifacts.static_analysis || {};
      const pe = staticAnalysis.pe || null;
      const source = staticAnalysis.source || null;
      const strings = staticAnalysis.strings || null;
      const telemetry = report.telemetry || {};
      const enabledModules = (telemetry.selected_modules || []).filter((m) => m.status === "enabled");
      const suspiciousImports = pe && pe.imports && Array.isArray(pe.imports.suspicious) ? pe.imports.suspicious : [];
      const sections = pe && Array.isArray(pe.sections) ? pe.sections.slice(0, 6) : [];

      const overviewSections = [
        `<section class="details-section">
          <h4>Report Summary</h4>
          ${renderDetailChips([
            { label: "Final", value: report.final_status || "-" },
            { label: "Score", value: report.score || 0 },
            { label: "Pass / Warn / Fail", value: `${severity.pass || 0} / ${severity.warn || 0} / ${severity.fail || 0}` },
            { label: "P50 / P95", value: `${runtimeSummary.p50_duration_ms || 0} / ${runtimeSummary.p95_duration_ms || 0} ms` },
            { label: "Flaky", value: formatBool(runtimeSummary.flaky) },
            { label: "Stability", value: `${runtimeSummary.stability_percent || 0}%` },
          ])}
        </section>`
      ];

      if (pe) {
        overviewSections.push(`
          <section class="details-section">
            <h4>PE Snapshot</h4>
            ${renderDetailChips([
              { label: "Architecture", value: pe.arch || "-" },
              { label: "DLL", value: formatBool(pe.is_dll) },
              { label: "Sections", value: pe.section_count || 0 },
              { label: "Overlay", value: formatShortBytes(pe.overlay_bytes || 0) },
              { label: "Certificate table", value: formatShortBytes(pe.certificate_table_bytes || 0) },
              { label: "Entry point RVA", value: pe.entry_point_rva != null ? `0x${Number(pe.entry_point_rva).toString(16).toUpperCase()}` : "-" },
            ])}
            ${renderDetailChips([
              { label: "DEP", value: formatBool(pe.mitigations && pe.mitigations.dep) },
              { label: "ASLR", value: formatBool(pe.mitigations && pe.mitigations.aslr) },
              { label: "CFG", value: formatBool(pe.mitigations && pe.mitigations.cfg) },
              { label: "Imports", value: pe.imports ? pe.imports.total || 0 : 0 },
            ])}
            ${suspiciousImports.length ? `<ul class="detail-list">${suspiciousImports.map((name) => `<li>${escapeHtml(name)}</li>`).join("")}</ul>` : `<div class="details-chip-v">No suspicious imports flagged.</div>`}
          </section>
        `);
      }

      if (sections.length) {
        overviewSections.push(`
          <section class="details-section">
            <h4>Sections</h4>
            <div class="trace-events">
              ${sections.map((section) => `
                <div class="trace-event">
                  <div class="trace-head">
                    <span>${escapeHtml(section.name || "?")}</span>
                    <span>H=${Number(section.entropy || 0).toFixed(2)}</span>
                  </div>
                  <div class="trace-detail">raw=${escapeHtml(formatShortBytes(section.raw_size || 0))} virt=${escapeHtml(formatShortBytes(section.virtual_size || 0))} R=${formatBool(section.readable)} W=${formatBool(section.writable)} X=${formatBool(section.executable)}</div>
                </div>
              `).join("")}
            </div>
          </section>
        `);
      }

      if (source) {
        overviewSections.push(`
          <section class="details-section">
            <h4>Source Snapshot</h4>
            ${renderDetailChips([
              { label: "Language", value: source.language || "-" },
              { label: "Lines", value: source.line_count || 0 },
              { label: "Mostly text", value: formatBool(source.mostly_text) },
              { label: "Long lines", value: source.long_lines || 0 },
              { label: "Unbalanced delimiters", value: formatBool(source.unbalanced_delimiters) },
              { label: "Suspicious hits", value: (source.suspicious_hits || []).length },
            ])}
          </section>
        `);
      }

      if (strings) {
        overviewSections.push(`
          <section class="details-section">
            <h4>Strings</h4>
            ${renderDetailChips([
              { label: "Scanned", value: strings.total_strings_scanned || 0 },
              { label: "Suspicious hits", value: (strings.suspicious_hits || []).length },
            ])}
            ${Array.isArray(strings.suspicious_hits) && strings.suspicious_hits.length ? `<ul class="detail-list">${strings.suspicious_hits.map((hit) => `<li>${escapeHtml(hit)}</li>`).join("")}</ul>` : `<div class="details-chip-v">No suspicious string hits recorded.</div>`}
          </section>
        `);
      }

      overviewSections.push(`
        <section class="details-section">
          <h4>Security-Lab</h4>
          ${renderDetailChips([
            { label: "Profile", value: telemetry.profile || "-" },
            { label: "Enabled modules", value: enabledModules.length },
            { label: "Disassembly signals", value: telemetry.coverage ? telemetry.coverage.disassembly_signals || 0 : 0 },
            { label: "Runtime traces", value: telemetry.coverage ? telemetry.coverage.runtime_traces || 0 : 0 },
          ])}
          ${enabledModules.length ? `<ul class="detail-list">${enabledModules.slice(0, 8).map((module) => `<li>${escapeHtml(module.id)}: ${escapeHtml(module.reason || "active")}</li>`).join("")}</ul>` : `<div class="details-chip-v">No active modules recorded.</div>`}
        </section>
      `);

      return overviewSections.join("");
    }

    function renderDetailsBox() {
      const details = document.getElementById("detailsBox");
      if (!state.report) {
        details.classList.remove("details-rich");
        details.textContent = state.logs.slice(-120).join("\n");
        return;
      }

      const runtimeRow = ((state.report && state.report.runtime) || []).find((row) => row.scenario === state.selectedScenario);
      details.classList.add("details-rich");
      details.innerHTML = `<div class="details-rich-wrap">${runtimeRow ? renderScenarioDetails(runtimeRow) : ""}${renderReportOverview(state.report)}</div>`;
      details.scrollTop = 0;
    }

    async function refreshTargetType(path) {
      const hint = document.getElementById("targetTypeHint");
      const trimmed = String(path || "").trim();
      if (!trimmed) {
        hint.textContent = `${tr("targetTypePrefix")} unknown`;
        return;
      }

      try {
        const info = await post("detect_target_type", { path: trimmed });
        const kind = String((info && info.kind) || "unknown");
        const lang = info && info.language ? ` (${info.language})` : "";
        hint.textContent = `${tr("targetTypePrefix")} ${kind}${lang}`;
        if (kind !== "executable") {
          addLog("[ui] " + tr("targetRuntimeSkipHint"));
        }
      } catch (e) {
        hint.textContent = `${tr("targetTypePrefix")} unknown`;
      }
    }

    function switchView(view) {
      state.view = view;
      document.querySelectorAll(".view").forEach(v => v.classList.add("hidden"));
      const target = document.querySelector("#view-" + view);
      if (target) {
        Array.from(target.children).forEach((child, idx) => {
          child.style.setProperty("--i", String(idx));
        });
        target.classList.remove("hidden");
        target.classList.remove("view-enter");
        requestAnimationFrame(() => target.classList.add("view-enter"));
      }
      const nav = Array.from(document.querySelectorAll(NAV_VIEW_SELECTOR));
      nav.forEach((b, i) => {
        b.classList.toggle("active", b.dataset.view === view);
        if (b.dataset.view === view) {
          document.getElementById("sidebar").style.setProperty("--nav-y", `${b.offsetTop}px`);
        }
      });
      document.getElementById("viewTitle").textContent = tr(viewKey(view));
    }

    function animateKpis() {
      document.querySelectorAll("#kpis .kpi").forEach((kpi) => {
        kpi.classList.remove("flash");
        requestAnimationFrame(() => kpi.classList.add("flash"));
      });
    }

    function animateCount(el, to, suffix = "") {
      const end = Number(to) || 0;
      const start = Number((el.textContent || "").replace(/[^\d.-]/g, "")) || 0;
      const delta = end - start;
      if (Math.abs(delta) < 1) {
        el.textContent = `${end}${suffix}`;
        return;
      }
      const t0 = performance.now();
      const dur = 210;
      const tick = (t) => {
        const p = Math.min(1, (t - t0) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        const v = Math.round(start + delta * eased);
        el.textContent = `${v}${suffix}`;
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }

    function applyInfographics(m) {
      const total = Math.max(1, m.pass + m.warn + m.fail);
      const passPct = Math.round((m.pass / total) * 100);
      const warnPct = Math.round((m.warn / total) * 100);
      const failPct = Math.round((m.fail / total) * 100);

      document.getElementById("infoPassBar").style.width = passPct + "%";
      document.getElementById("infoWarnBar").style.width = warnPct + "%";
      document.getElementById("infoFailBar").style.width = failPct + "%";
      document.getElementById("infoStabilityBar").style.width = m.stability + "%";

      animateCount(document.getElementById("infoPassPct"), passPct, "%");
      animateCount(document.getElementById("infoWarnPct"), warnPct, "%");
      animateCount(document.getElementById("infoFailPct"), failPct, "%");
      animateCount(document.getElementById("infoStability"), m.stability, "%");
    }

    function formatSize(v) {
      if (v < 1024) return v + " B";
      if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KB";
      return (v / (1024 * 1024)).toFixed(2) + " MB";
    }

    function percentile(values, p) {
      if (!values.length) return 0;
      const sorted = values.slice().sort((a, b) => a - b);
      const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1));
      return sorted[idx] || 0;
    }

    function computeMetrics(report) {
      const findings = report.findings || [];
      const runtime = report.runtime || [];
      let pass = 0;
      let warn = 0;
      let fail = 0;
      for (const f of findings) {
        if (f.severity === "PASS") pass++;
        else if (f.severity === "WARN") warn++;
        else if (f.severity === "FAIL") fail++;
      }

      const durations = runtime.map(r => Number(r.duration_ms || 0)).filter(v => Number.isFinite(v));
      const total = runtime.length || 1;
      const unstable = runtime.filter(r => r.timed_out || Number(r.exit_code) !== 0).length;
      const flakiness = Math.round((unstable / total) * 100);
      const stability = Math.max(0, 100 - flakiness);

      return {
        pass,
        warn,
        fail,
        p50: Math.round(percentile(durations, 50)),
        p95: Math.round(percentile(durations, 95)),
        flakiness,
        stability,
        durations,
        runtime
      };
    }

    function cssVar(name, fallback) {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    }

    function drawSeverityDonut(metrics, progress = 1) {
      const c = document.getElementById("severityCanvas");
      const ctx = c.getContext("2d");
      const w = c.width;
      const h = c.height;
      ctx.clearRect(0, 0, w, h);

      const total = Math.max(1, metrics.pass + metrics.warn + metrics.fail);
      const vals = [
        { v: metrics.pass, color: cssVar("--ok", "#4dbd7b"), label: "PASS" },
        { v: metrics.warn, color: cssVar("--warn", "#dfac62"), label: "WARN" },
        { v: metrics.fail, color: cssVar("--fail", "#de6f6f"), label: "FAIL" }
      ];

      const cx = 72;
      const cy = 70;
      const r = 46;
      const ring = 12;
      let a = -Math.PI / 2;
      const ringProgress = Math.max(0, Math.min(1, progress));

      vals.forEach((it) => {
        const part = ((it.v / total) * Math.PI * 2) * ringProgress;
        ctx.beginPath();
        ctx.strokeStyle = it.color;
        ctx.lineWidth = ring;
        ctx.arc(cx, cy, r, a, a + part);
        ctx.stroke();
        a += part;
      });

      ctx.beginPath();
      ctx.fillStyle = cssVar("--bg-ink", "#121212");
      ctx.arc(cx, cy, r - ring, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = cssVar("--text", "#e7e7e7");
      ctx.font = "700 17px Segoe UI";
      ctx.textAlign = "center";
      ctx.fillText(String(Math.round(total * ringProgress)), cx, cy + 6);

      ctx.textAlign = "left";
      let y = 34;
      vals.forEach((it) => {
        ctx.fillStyle = it.color;
        ctx.fillRect(150, y - 8, 11, 11);
        ctx.fillStyle = cssVar("--muted", "#b0b0b0");
        ctx.font = "12px Cascadia Code";
        ctx.fillText(`${it.label}: ${Math.round(it.v * ringProgress)}`, 167, y + 1);
        y += 24;
      });
    }

    function drawRuntimeChart(metrics, progress = 1) {
      const c = document.getElementById("runtimeCanvas");
      const ctx = c.getContext("2d");
      const accent = cssVar("--accent", "#ff6b2e");
      const accent2 = cssVar("--accent-2", "#ff9d2e");
      const w = c.width;
      const h = c.height;
      ctx.clearRect(0, 0, w, h);

      ctx.fillStyle = cssVar("--bg-ink", "#121212");
      ctx.fillRect(0, 0, w, h);

      const values = metrics.durations;
      if (!values.length) {
        ctx.fillStyle = cssVar("--muted", "#a3a3a3");
        ctx.font = "12px Cascadia Code";
        ctx.fillText(tr("noRuntimeData"), 12, 20);
        return;
      }

      const pad = { l: 28, r: 10, t: 10, b: 20 };
      const chartW = w - pad.l - pad.r;
      const chartH = h - pad.t - pad.b;
      const maxV = Math.max(1, Math.max(...values));
      const p50 = metrics.p50;
      const p95 = metrics.p95;
      const drawProgress = Math.max(0, Math.min(1, progress));

      ctx.strokeStyle = cssVar("--line-soft", "#2a2a2a");
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = pad.t + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad.l, y);
        ctx.lineTo(w - pad.r, y);
        ctx.stroke();
      }

      const step = values.length > 1 ? chartW / (values.length - 1) : chartW;
      const linePoints = [];
      ctx.beginPath();
      ctx.strokeStyle = accent;
      ctx.lineWidth = 2;
      const visibleIndex = drawProgress * (values.length - 1);
      const lastFull = Math.floor(visibleIndex);
      values.forEach((v, i) => {
        if (i > lastFull + 1) return;
        const x = pad.l + i * step;
        const y = pad.t + chartH - (v / maxV) * chartH;
        linePoints.push({ x, y, v });
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      if (lastFull + 1 < values.length) {
        const i0 = Math.max(0, lastFull);
        const i1 = Math.min(values.length - 1, lastFull + 1);
        if (i1 !== i0) {
          const t = visibleIndex - i0;
          const x0 = pad.l + i0 * step;
          const y0 = pad.t + chartH - (values[i0] / maxV) * chartH;
          const x1 = pad.l + i1 * step;
          const y1 = pad.t + chartH - (values[i1] / maxV) * chartH;
          const px = x0 + (x1 - x0) * t;
          const py = y0 + (y1 - y0) * t;
          ctx.lineTo(px, py);
          linePoints.push({ x: px, y: py, v: values[i0] + (values[i1] - values[i0]) * t });
        }
      }

      if (linePoints.length > 1) {
        const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + chartH);
        grad.addColorStop(0, cssVar("--accent-glow", "rgba(255, 107, 46, 0.24)"));
        grad.addColorStop(1, "rgba(0,0,0,0)");
        ctx.save();
        ctx.globalAlpha = 0.48;
        ctx.beginPath();
        ctx.moveTo(linePoints[0].x, pad.t + chartH);
        linePoints.forEach((p) => ctx.lineTo(p.x, p.y));
        const last = linePoints[linePoints.length - 1];
        ctx.lineTo(last.x, pad.t + chartH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
        ctx.restore();
      }

      ctx.stroke();

      if (linePoints.length > 0) {
        const tail = linePoints[linePoints.length - 1];
        ctx.beginPath();
        ctx.fillStyle = accent2;
        ctx.arc(tail.x, tail.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.globalAlpha = 0.35 + drawProgress * 0.25;
        ctx.arc(tail.x, tail.y, 8, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      const drawThreshold = (val, color, label) => {
        const y = pad.t + chartH - (val / maxV) * chartH;
        ctx.strokeStyle = color;
        ctx.setLineDash([5, 5]);
        ctx.beginPath();
        ctx.moveTo(pad.l, y);
        ctx.lineTo(w - pad.r, y);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = color;
        ctx.globalAlpha = drawProgress;
        ctx.font = "11px Cascadia Code";
        ctx.fillText(`${label}: ${val}ms`, pad.l + 6, y - 4);
        ctx.globalAlpha = 1;
      };

      drawThreshold(p50, accent2, "p50");
      drawThreshold(p95, cssVar("--fail", "#de6f6f"), "p95");

      ctx.fillStyle = cssVar("--muted", "#a3a3a3");
      ctx.font = "11px Cascadia Code";
      ctx.fillText(`max=${maxV}ms`, w - 95, 14);
    }

    function animateCharts(metrics) {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        drawSeverityDonut(metrics, 1);
        drawRuntimeChart(metrics, 1);
        return;
      }
      const started = performance.now();
      const dur = 520;
      const tick = (now) => {
        const p = Math.min(1, (now - started) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        drawSeverityDonut(metrics, eased);
        drawRuntimeChart(metrics, eased);
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }

    function applyMetrics(report) {
      const m = computeMetrics(report);
      animateCount(document.getElementById("kWarn"), m.warn);
      animateCount(document.getElementById("kFail"), m.fail);
      animateCount(document.getElementById("kP50"), m.p50);
      animateCount(document.getElementById("kP95"), m.p95);

      document.getElementById("dStatus").textContent = report.final_status || "-";
      document.getElementById("dFindings").textContent = String((report.findings || []).length);
      document.getElementById("dRuntime").textContent = String((report.runtime || []).length);
      document.getElementById("dFlakiness").textContent = `${m.flakiness}%`;
      document.getElementById("dStability").textContent = `${m.stability}%`;

      animateCharts(m);
      applyInfographics(m);
      animateKpis();
    }

    function applySettingsToUi(s) {
      const rawTheme = String((s && s.theme) || "AUTO").toUpperCase();
      const looksLikeThemeMode = THEME_MODE_OPTIONS.includes(rawTheme);
      const accentFromLegacy = looksLikeThemeMode ? "AMETHYST" : rawTheme;
      const accent = normalizeAccent((s && s.accent) || accentFromLegacy);
      const themeMode = normalizeThemeMode(looksLikeThemeMode ? rawTheme : "AUTO");

      document.getElementById("langSelect").value = s.language || "auto";
      document.getElementById("accentSelect").value = accent;
      document.getElementById("themeModeSelect").value = themeMode;
      document.getElementById("defaultModeSelect").value = s.default_mode || "MIN";
      document.getElementById("defaultPowerProfileSelect").value = normalizePowerProfile(s.power_profile || "BASIC");
      document.getElementById("defaultSandboxProfileSelect").value = normalizeSandboxProfile(s.sandbox_profile || "limited");
      document.getElementById("settingsOutDir").value = s.out_dir || "logs";
      document.getElementById("outDirInput").value = s.out_dir || "logs";
        document.getElementById("analyzerPathInput").value = s.analyzer_path || "";
      document.getElementById("modeSelect").value = s.default_mode || "MIN";
      document.getElementById("powerProfileSelect").value = normalizePowerProfile(s.power_profile || "BASIC");
      document.getElementById("sandboxProfileSelect").value = normalizeSandboxProfile(s.sandbox_profile || "limited");
      document.getElementById("verdictModeSelect").value = normalizeVerdictMode(s.default_mode === "PENTEST" ? "STRICT" : "BALANCED");

      applyAccent(accent);
      applyThemeMode(themeMode);
      document.getElementById("modeBadge").textContent = tr("lblMode").toUpperCase() + ": " + (s.default_mode || "MIN");
      document.getElementById("stMode").textContent = "mode=" + (s.default_mode || "MIN");
      document.getElementById("stSandbox").textContent = "sandbox=" + normalizeSandboxProfile(s.sandbox_profile || "limited");
      refreshTargetType(document.getElementById("targetPath").value).catch(() => {});

      const selected = (s.language || "auto").toLowerCase();
      state.lang = selected === "auto" ? pickLang("") : pickLang(selected);
      applyTexts();
      syncEnhancedSelects();
    }

    async function loadSettings() {
      const s = await post("load_settings", {});
      state.settings = s;
      applySettingsToUi(s);
      switchView(state.view);
    }

    async function saveUiSettings() {
      const settings = {
        language: document.getElementById("langSelect").value,
        theme: normalizeThemeMode(document.getElementById("themeModeSelect").value),
        accent: normalizeAccent(document.getElementById("accentSelect").value),
        default_mode: document.getElementById("defaultModeSelect").value,
        power_profile: normalizePowerProfile(document.getElementById("defaultPowerProfileSelect").value),
        sandbox_profile: normalizeSandboxProfile(document.getElementById("defaultSandboxProfileSelect").value),
        out_dir: document.getElementById("settingsOutDir").value || "logs",
        analyzer_path: document.getElementById("analyzerPathInput").value.trim() || null
      };
      await post("save_settings", settings);
      state.settings = settings;
      applySettingsToUi(settings);
      addLog("[ui] interface settings saved");
      flashNote(tr("settingsSaved"));
    }

    async function listReports() {
      const outDir = document.getElementById("outDirInput").value || "logs";
      const rows = await post("list_reports", { out_dir: outDir });
      state.reports = rows || [];
      const tbody = document.querySelector("#reportsTable tbody");
      tbody.innerHTML = "";
      for (const r of state.reports) {
        const row = document.createElement("tr");
        const date = new Date((r.modified_unix || 0) * 1000).toLocaleString();
        row.innerHTML = `<td>${date}</td><td>${formatSize(r.size_bytes || 0)}</td><td>${r.path}</td><td><button class="btn" data-open="${r.path}">${tr("btnOpen")}</button></td>`;
        tbody.appendChild(row);
      }
      tbody.querySelectorAll("button[data-open]").forEach(btn => {
        btn.addEventListener("click", async () => {
          const path = btn.getAttribute("data-open");
          await loadReport(path);
          switchView("reports");
        });
      });
    }

    function addFindingRow(tbody, f) {
      const tr = document.createElement("tr");
      const sevClass = f.severity === "PASS" ? "sev-pass" : f.severity === "WARN" ? "sev-warn" : "sev-fail";
      tr.innerHTML = `<td class="${sevClass}">${f.severity || "-"}</td><td class="mono">${f.code || "-"}</td><td>${f.category || "-"}</td><td>${f.points || 0}</td><td>${f.message || ""}</td>`;
      tbody.appendChild(tr);
    }

    function renderFindings() {
      const tbody = document.querySelector("#findingsTable tbody");
      tbody.innerHTML = "";
      const source = (state.report && state.report.findings) || [];
      const needle = (document.getElementById("findingSearch").value || "").toLowerCase();
      const sevFilter = document.getElementById("severityFilter").value;
      const groupFilter = document.getElementById("groupFilter").value;

      const filtered = source.filter(f => {
        const keepSev = sevFilter === "ALL" || f.severity === sevFilter;
        const text = `${f.code} ${f.category} ${f.message}`.toLowerCase();
        return keepSev && (!needle || text.includes(needle));
      });

      if (groupFilter !== "none") {
        const map = new Map();
        for (const f of filtered) {
          const key = f[groupFilter] || "other";
          if (!map.has(key)) map.set(key, []);
          map.get(key).push(f);
        }
        for (const [group, items] of map.entries()) {
          const head = document.createElement("tr");
          head.innerHTML = `<td colspan="5" class="mono muted">${String(group).toUpperCase()} (${items.length})</td>`;
          tbody.appendChild(head);
          for (const f of items) addFindingRow(tbody, f);
        }
      } else {
        filtered.forEach(f => addFindingRow(tbody, f));
      }
    }

    function renderRuntime() {
      const tbody = document.querySelector("#runtimeTable tbody");
      tbody.innerHTML = "";
      const runtime = (state.report && state.report.runtime) || [];
      for (const r of runtime) {
        const row = document.createElement("tr");
        row.classList.toggle("is-selected", state.selectedScenario === (r.scenario || null));
        row.innerHTML = `<td>${r.scenario || "-"}</td><td>${r.exit_code}</td><td>${r.timed_out ? tr("yes") : tr("no")}</td><td>${r.duration_ms || 0}</td><td>${r.stdout_len || 0}</td><td>${r.stderr_len || 0}</td>`;
        row.addEventListener("click", () => {
          state.selectedScenario = r.scenario || null;
          document.getElementById("detailsMeta").textContent = tr("scenarioPrefix") + (state.selectedScenario || "-");
          document.getElementById("dScenario").textContent = state.selectedScenario || "-";
          tbody.querySelectorAll("tr").forEach((item) => item.classList.remove("is-selected"));
          row.classList.add("is-selected");
          renderDetailsBox();
        });
        tbody.appendChild(row);
      }
    }

    async function loadReport(path) {
      const data = await post("open_report", { path });
      state.report = data;
      state.reportPath = path;
      state.selectedScenario = null;
      document.getElementById("detailsMeta").textContent = "-";
      document.getElementById("dScenario").textContent = "-";
      document.getElementById("reportHint").textContent = path;
      document.getElementById("kStatus").textContent = data.final_status || "-";
      document.getElementById("kScore").textContent = String(data.score || 0);
      document.getElementById("stVersion").textContent = "schema=" + (data.schema_version || "v1");
      applyMetrics(data);
      renderFindings();
      renderRuntime();
      renderDetailsBox();
      document.getElementById("reportsFindingsSection").classList.remove("hidden");
    }

    function clearCurrentReport() {
      state.report = null;
      state.reportPath = null;
      state.selectedScenario = null;
      document.getElementById("reportHint").textContent = tr("noReport");
      document.getElementById("detailsMeta").textContent = "-";
      document.getElementById("dScenario").textContent = "-";
      document.getElementById("kStatus").textContent = tr("statusIdle");
      document.getElementById("kScore").textContent = "0";
      document.getElementById("kWarn").textContent = "0";
      document.getElementById("kFail").textContent = "0";
      document.getElementById("kP50").textContent = "0";
      document.getElementById("kP95").textContent = "0";
      document.getElementById("dStatus").textContent = "-";
      document.getElementById("dFindings").textContent = "0";
      document.getElementById("dRuntime").textContent = "0";
      document.getElementById("dFlakiness").textContent = "0%";
      document.getElementById("dStability").textContent = "0%";
      document.getElementById("infoPassBar").style.width = "0%";
      document.getElementById("infoWarnBar").style.width = "0%";
      document.getElementById("infoFailBar").style.width = "0%";
      document.getElementById("infoStabilityBar").style.width = "0%";
      document.getElementById("infoPassPct").textContent = "0%";
      document.getElementById("infoWarnPct").textContent = "0%";
      document.getElementById("infoFailPct").textContent = "0%";
      document.getElementById("infoStability").textContent = "0%";
      document.querySelector("#findingsTable tbody").innerHTML = "";
      document.querySelector("#runtimeTable tbody").innerHTML = "";
      document.getElementById("reportsFindingsSection").classList.add("hidden");
      drawSeverityDonut({ pass: 0, warn: 0, fail: 0 });
      drawRuntimeChart({ durations: [], p50: 0, p95: 0 });
      renderDetailsBox();
      flashNote(tr("reportClosed"));
    }

    async function openReportLog(kind) {
      const reportPath = state.reportPath || document.getElementById("reportHint").textContent;
      if (!reportPath || reportPath === tr("noReport")) {
        addLog("[ui] " + tr("noReport"));
        return;
      }
      const payload = await post("list_logs_for_report", { report_path: reportPath });
      const selected = kind === "full" ? payload.full_log : payload.issues_log;
      if (!selected) {
        addLog("[ui] log file not found for report");
        return;
      }
      await post("open_path", { path: selected });
      addLog("[reports] opened log: " + selected);
    }

    function startProgress() {
      state.runStart = Date.now();
      if (state.progressTick) clearInterval(state.progressTick);
      state.progressTick = setInterval(() => {
        const elapsed = (Date.now() - state.runStart) / 1000;
        const runs = Number(document.getElementById("runsInput").value || "6");
        const timeout = Number(document.getElementById("timeoutInput").value || "4");
        const expected = Math.max(1, runs * timeout);
        const p = Math.min(96, Math.round((elapsed / expected) * 100));
        document.getElementById("runProgress").style.width = p + "%";
      }, 250);
    }

    function endProgress() {
      if (state.progressTick) {
        clearInterval(state.progressTick);
        state.progressTick = null;
      }
      document.getElementById("runProgress").style.width = "100%";
      setTimeout(() => {
        document.getElementById("runProgress").style.width = "0%";
      }, 600);
    }

    async function runAnalysis() {
      const targetPath = document.getElementById("targetPath").value;
      const targetInfo = await post("detect_target_type", { path: targetPath });
      if (String(targetInfo.kind || "unknown") !== "executable") {
        addLog("[ui] " + tr("targetExecutableRequired"));
        addLog("[ui] " + tr("targetRuntimeSkipHint"));
        flashNote(tr("targetExecutableRequired"));
        document.getElementById("kStatus").textContent = tr("statusIdle");
        document.getElementById("stRun").textContent = "analysis=blocked-non-executable";
        return;
      }

      const payload = {
        target_path: targetPath,
        mode: document.getElementById("modeSelect").value,
        verdict_mode: normalizeVerdictMode(document.getElementById("verdictModeSelect").value),
        power_profile: normalizePowerProfile(document.getElementById("powerProfileSelect").value),
        sandbox_profile: normalizeSandboxProfile(document.getElementById("sandboxProfileSelect").value),
        runs: Number(document.getElementById("runsInput").value || "6"),
        timeout_secs: Number(document.getElementById("timeoutInput").value || "4"),
        out_dir: document.getElementById("outDirInput").value || "logs",
        assignment_path: (document.getElementById("assignmentPathInput")?.value || "").trim() || null,
        audit_dir: (document.getElementById("auditDirInput")?.value || "").trim() || null,
        confirm_pentest: document.getElementById("confirmPentest").checked
      };

      document.getElementById("stSandbox").textContent = "sandbox=" + payload.sandbox_profile;

      state.logs.length = 0;
      addLog("[ui] starting analysis...");
      document.getElementById("kStatus").textContent = tr("statusRunning");
      document.getElementById("stRun").textContent = "analysis=running";
      startProgress();
      await post("run_analysis", payload);
    }

    async function stopAnalysis() {
      await post("stop_analysis", {});
      document.getElementById("stRun").textContent = "analysis=stop-requested";
      flashNote(tr("stopRequested"));
    }

    async function exportReport(format) {
      const reportPath = document.getElementById("reportHint").textContent;
      if (!reportPath || reportPath === tr("noReport")) {
        addLog("[ui] " + tr("noReport"));
        return;
      }
      const payload = await post("export_report", {
        report_path: reportPath,
        format: String(format || "").toLowerCase() === "html" ? "html" : "md"
      });
      if (payload && payload.path) {
        addLog("[export] " + payload.path);
      }
    }

    async function createBundle() {
      const reportPath = document.getElementById("reportHint").textContent;
      if (!reportPath || reportPath === tr("noReport")) {
        addLog("[ui] " + tr("noReportForBundle"));
        return;
      }
      const payload = await post("create_repro_bundle", {
        report_path: reportPath,
        target_path: document.getElementById("targetPath").value,
        mode: document.getElementById("modeSelect").value
      });
      addLog("[bundle] " + payload.path);
      flashNote(tr("bundleCreated"));
    }

    async function rerunScenario() {
      if (!state.selectedScenario) {
        addLog("[ui] " + tr("selectScenarioFirst"));
        return;
      }
      await post("rerun_scenario", {
        scenario: state.selectedScenario,
        target_path: document.getElementById("targetPath").value,
        mode: document.getElementById("modeSelect").value
      });
      addLog("[runtime] rerun requested: " + state.selectedScenario);
    }

    
