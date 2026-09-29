(function () {
	const MAX_TIMELINE_POINTS = 24;
	const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 84;
	const reconnectBaseDelay = 1500;
	const METRIC_HISTORY_LIMIT = 32;
	const TREND_WINDOW_MS = 60 * 1000;
	const SPARKLINE_WINDOW_MS = 3 * 60 * 1000;
	const SPARKLINE_BINS = 10;
	const HEALTH_REFRESH_MS = 5000;

	const ui = {
		body: document.body,
		connectionStatus: document.getElementById("bridge-connection-status"),
		lastUpdateLabel: document.getElementById("last-update-label"),
		alertBanner: document.getElementById("alert-banner"),
		alertBannerKicker: document.getElementById("alert-banner-kicker"),
		alertBannerTitle: document.getElementById("alert-banner-title"),
		alertBannerCopy: document.getElementById("alert-banner-copy"),
		postureIndicator: document.getElementById("posture-indicator"),
		globalRiskScore: document.getElementById("global-risk-score"),
		globalRiskLevel: document.getElementById("global-risk-level"),
		globalPostureCopy: document.getElementById("global-posture-copy"),
		gaugeRing: document.getElementById("gauge-ring"),
		activeThreatCount: document.getElementById("active-threat-count"),
		activeThreatTrend: document.getElementById("active-threat-trend"),
		activeThreatDelta: document.getElementById("active-threat-delta"),
		activeThreatSpark: document.getElementById("active-threat-spark"),
		eventCount: document.getElementById("event-count"),
		eventCountTrend: document.getElementById("event-count-trend"),
		eventCountDelta: document.getElementById("event-count-delta"),
		eventCountSpark: document.getElementById("event-count-spark"),
		elevatedEventCount: document.getElementById("elevated-event-count"),
		elevatedEventTrend: document.getElementById("elevated-event-trend"),
		elevatedEventDelta: document.getElementById("elevated-event-delta"),
		elevatedEventSpark: document.getElementById("elevated-event-spark"),
		healthySourceCount: document.getElementById("healthy-source-count"),
		healthySourceTrend: document.getElementById("healthy-source-trend"),
		healthySourceDelta: document.getElementById("healthy-source-delta"),
		healthySourceSpark: document.getElementById("healthy-source-spark"),
		feedSummary: document.getElementById("feed-summary"),
		feedList: document.getElementById("feed-list"),
		feedSearchInput: document.getElementById("feed-search-input"),
		feedSourceFilter: document.getElementById("feed-source-filter"),
		feedSortOrder: document.getElementById("feed-sort-order"),
		feedFilters: Array.from(document.querySelectorAll(".feed-filter")),
		priorityActionTitle: document.getElementById("priority-action-title"),
		priorityActionMeta: document.getElementById("priority-action-meta"),
		priorityActionResponse: document.getElementById("priority-action-response"),
		incidentEmpty: document.getElementById("incident-empty"),
		incidentContent: document.getElementById("incident-content"),
		incidentOperatorState: document.getElementById("incident-operator-state"),
		incidentTitle: document.getElementById("incident-title"),
		incidentLevel: document.getElementById("incident-level"),
		incidentSourceChip: document.getElementById("incident-source-chip"),
		incidentSummary: document.getElementById("incident-summary"),
		incidentScore: document.getElementById("incident-score"),
		incidentOrigin: document.getElementById("incident-origin"),
		incidentSource: document.getElementById("incident-source"),
		incidentStatus: document.getElementById("incident-status"),
		incidentObserved: document.getElementById("incident-observed"),
		incidentAction: document.getElementById("incident-action"),
		incidentId: document.getElementById("incident-id"),
		incidentSourceSystem: document.getElementById("incident-source-system"),
		incidentSourceType: document.getElementById("incident-source-type"),
		incidentCategory: document.getElementById("incident-category"),
		incidentObservedDetail: document.getElementById("incident-observed-detail"),
		incidentIngested: document.getElementById("incident-ingested"),
		incidentRawSeverity: document.getElementById("incident-raw-severity"),
		incidentRiskScoreDetail: document.getElementById("incident-risk-score-detail"),
		incidentStatusDetail: document.getElementById("incident-status-detail"),
		incidentRaw: document.getElementById("incident-raw"),
		mitigateButton: document.getElementById("mitigate-button"),
		containmentStatus: document.getElementById("containment-status"),
		containmentTitle: document.getElementById("containment-title"),
		containmentMessage: document.getElementById("containment-message"),
		healthBridge: document.getElementById("health-bridge"),
		healthLegacy: document.getElementById("health-legacy"),
		healthSim: document.getElementById("health-sim"),
		aiModelStatus: document.getElementById("ai-model-status"),
		aiRefreshButton: document.getElementById("ai-refresh-button"),
		aiGenerateButton: document.getElementById("ai-generate-button"),
		aiAnalystMessage: document.getElementById("ai-analyst-message"),
		aiBrief: document.getElementById("ai-brief"),
		aiOverallAssessment: document.getElementById("ai-overall-assessment"),
		aiKeyFindings: document.getElementById("ai-key-findings"),
		aiCampaignHypotheses: document.getElementById("ai-campaign-hypotheses"),
		aiRecommendedActions: document.getElementById("ai-recommended-actions"),
		aiLimitations: document.getElementById("ai-limitations"),
		aiBriefMeta: document.getElementById("ai-brief-meta"),
		autoMitigateToggle: document.getElementById("auto-mitigate-toggle"),
		autoMitigateMessage: document.getElementById("auto-mitigate-message"),
		simulatorSummaryStatus: document.getElementById("simulator-summary-status"),
		legacyLaunchStatus: document.getElementById("legacy-launch-status"),
		legacyStartButton: document.getElementById("legacy-start-button"),
		legacyStopButton: document.getElementById("legacy-stop-button"),
		legacyLaunchMessage: document.getElementById("legacy-launch-message"),
		attackLaunchStatus: document.getElementById("attack-launch-status"),
		attackTypeOptions: document.getElementById("attack-type-options"),
		attackStartButton: document.getElementById("attack-start-button"),
		attackStopButton: document.getElementById("attack-stop-button"),
		attackLaunchMessage: document.getElementById("attack-launch-message"),
		investigationHistory: document.getElementById("investigation-history"),
		historyDays: document.getElementById("history-days"),
		historySummaryMeta: document.getElementById("history-summary-meta"),
		historyTimeline: document.getElementById("history-timeline"),
		historySeverityDonut: document.getElementById("history-severity-donut"),
		historySeverityLegend: document.getElementById("history-severity-legend"),
		historyCategoryChart: document.getElementById("history-category-chart"),
		historySourceChart: document.getElementById("history-source-chart"),
		historyEventList: document.getElementById("history-event-list"),
		historyLoadMore: document.getElementById("history-load-more"),
		historyError: document.getElementById("history-error"),
		timelineChart: document.getElementById("timeline-chart"),
		timelineSummary: document.getElementById("timeline-summary"),
		timelineDetail: document.getElementById("timeline-detail"),
		distributionChart: document.getElementById("distribution-chart"),
		distributionSummary: document.getElementById("distribution-summary"),
		sourceActivityChart: document.getElementById("source-activity-chart"),
		sourceActivitySummary: document.getElementById("source-activity-summary")
	};

	const state = {
		events: [],
		sourceHealth: {},
		bridgeStatus: "connecting",
		globalRiskScore: 0,
		globalThreatLevel: "low",
		activeEventCount: 0,
		selectedEventId: null,
		lastUpdatedAt: null,
		mitigationPending: false,
		mitigationResult: null,
		eventMitigationError: null,
		eventMitigationsPending: new Set(),
		aiStatus: null,
		aiPending: false,
		aiBriefResult: null,
		aiError: null,
		autoMitigation: { enabled: true, threshold: 199, batch_size: 5 },
		simulatorStatus: { attack_sim: { running: false, attack_types: [] }, legacy_api: { running: false, online: false, managed: false } },
		simulatorPending: false,
		selectedAttackTypes: new Set(),
		historyOffset: 0,
		historyEvents: [],
		historyLoading: false,
		reconnectAttempt: 0,
		eventSource: null,
		healthRefreshTimer: null,
		lastHighlightedEventId: null,
		lastMetricsSignature: "",
		metricHistory: {
			active: [],
			recent: [],
			elevated: [],
			healthy: []
		},
		feed: {
			severity: "all",
			source: "all",
			search: "",
			sort: "newest"
		}
	};

	function init() {
		ui.gaugeRing.style.strokeDasharray = String(GAUGE_CIRCUMFERENCE);
		ui.gaugeRing.style.strokeDashoffset = String(GAUGE_CIRCUMFERENCE);
		ui.mitigateButton.addEventListener("click", handleMitigationRequest);
		ui.aiRefreshButton.addEventListener("click", refreshAiStatus);
		ui.aiGenerateButton.addEventListener("click", handleAiBriefRequest);
		ui.autoMitigateToggle.addEventListener("change", handleAutoMitigationToggle);
		ui.legacyStartButton.addEventListener("click", () => handleSimulatorRequest("/api/simulators/legacy/start", {}, "legacy"));
		ui.legacyStopButton.addEventListener("click", () => handleSimulatorRequest("/api/simulators/legacy/stop", {}, "legacy"));
		ui.attackStartButton.addEventListener("click", () => {
			const attackTypes = Array.from(ui.attackTypeOptions.querySelectorAll("input[name='attack-type']:checked")).map((item) => item.value);
			handleSimulatorRequest("/api/simulators/attack/start", { attack_types: attackTypes }, "attack");
		});
		ui.attackStopButton.addEventListener("click", () => handleSimulatorRequest("/api/simulators/attack/stop", {}, "attack"));
		ui.attackTypeOptions.addEventListener("change", (event) => {
			if (event.target.matches("input[name='attack-type']")) {
				state.selectedAttackTypes = new Set(Array.from(ui.attackTypeOptions.querySelectorAll("input:checked")).map((item) => item.value));
				renderSimulatorControls();
			}
		});
		ui.investigationHistory.addEventListener("toggle", () => { if (ui.investigationHistory.open) loadInvestigationHistory(true); });
		ui.historyDays.addEventListener("change", () => loadInvestigationHistory(true));
		ui.historyLoadMore.addEventListener("click", () => loadInvestigationHistory(false));
		ui.feedSearchInput.addEventListener("input", (event) => {
			state.feed.search = event.target.value || "";
			renderOperatorQueue(state.lastHighlightedEventId);
		});
		ui.feedSourceFilter.addEventListener("click", (event) => {
			const button = event.target.closest("[data-source]");
			if (!button) return;
			state.feed.source = button.dataset.source;
			ui.feedSourceFilter.querySelectorAll("[data-source]").forEach((candidate) => {
				candidate.classList.toggle("active", candidate === button);
			});
			renderOperatorQueue(state.lastHighlightedEventId);
		});
		ui.feedSortOrder.addEventListener("click", (event) => {
			const button = event.target.closest("[data-sort]");
			if (!button) return;
			state.feed.sort = button.dataset.sort;
			ui.feedSortOrder.querySelectorAll("[data-sort]").forEach((candidate) => {
				candidate.classList.toggle("active", candidate === button);
			});
			renderOperatorQueue(state.lastHighlightedEventId);
		});
		ui.feedFilters.forEach((button) => {
			button.addEventListener("click", () => {
				state.feed.severity = button.dataset.severity || "all";
				ui.feedFilters.forEach((candidate) => {
					candidate.classList.toggle("active", candidate === button);
				});
				renderOperatorQueue(state.lastHighlightedEventId);
			});
		});
		bootstrap();
		startHealthRefreshLoop();
	}

	async function bootstrap() {
		setBridgeStatus("connecting");

		try {
			const [stateResponse, healthResponse] = await Promise.all([
				fetchJson("/api/state"),
				fetchJson("/api/health")
			]);

			ingestState(stateResponse);
			applyHealthResponse(healthResponse);
			await refreshSimulatorStatus();
			renderAll();
			setBridgeStatus("online");
			refreshAiStatus();
		} catch (error) {
			console.error("Initial dashboard bootstrap failed.", error);
			setBridgeStatus("reconnecting");
			ui.globalPostureCopy.textContent = "Attempting to recover bridge connectivity.";
		}

		connectEventStream();
	}

	async function fetchJson(url) {
		const response = await fetch(url, { headers: { Accept: "application/json" } });
		if (!response.ok) {
			const staleBackend = response.status === 404 && (url.startsWith("/api/history/") || url.startsWith("/api/simulators/"));
			const hint = staleBackend ? ". Restart the bridge from this project checkout to load the current API." : "";
			throw new Error(`Request failed for ${url} with status ${response.status}${hint}`);
		}

		return response.json();
	}

	function connectEventStream() {
		if (state.eventSource) {
			state.eventSource.close();
		}

		const eventSource = new EventSource("/api/events/stream");
		state.eventSource = eventSource;

		eventSource.addEventListener("open", () => {
			state.reconnectAttempt = 0;
			setBridgeStatus("online");
		});

		eventSource.addEventListener("state", (event) => {
			const payload = parseEventData(event);
			if (!payload) {
				return;
			}

			ingestState(payload);
			renderAll();
		});

		eventSource.addEventListener("event", (event) => {
			const payload = parseEventData(event);
			if (!payload) {
				return;
			}

			state.lastHighlightedEventId = payload.id;
			upsertEvent(payload, true);
			updateDerivedMetrics();
			autoSelectCurrentThreat(payload.id);
			renderAll({ highlightEventId: payload.id });
		});

		eventSource.onerror = async () => {
			eventSource.close();
			setBridgeStatus("reconnecting");

			try {
				applyHealthResponse(await fetchJson("/api/health"));
				renderHealth();
			} catch (error) {
				console.warn("Health refresh failed during SSE reconnect.", error);
			}

			scheduleReconnect();
		};
	}

	function startHealthRefreshLoop() {
		if (state.healthRefreshTimer) {
			window.clearInterval(state.healthRefreshTimer);
		}
		state.healthRefreshTimer = window.setInterval(refreshHealthSnapshot, HEALTH_REFRESH_MS);
	}

	async function refreshHealthSnapshot() {
		try {
			applyHealthResponse(await fetchJson("/api/health"));
			renderAll();
		} catch (error) {
			console.warn("Periodic health refresh failed.", error);
		}
		refreshAiStatus();
		refreshSimulatorStatus();
	}

	async function refreshSimulatorStatus() {
		try {
			state.simulatorStatus = await fetchJson("/api/simulators/status");
			if (state.simulatorStatus.attack_sim?.running) {
				state.selectedAttackTypes = new Set(state.simulatorStatus.attack_sim.attack_types || []);
			}
		} catch (error) {
			console.warn("Simulator status refresh failed.", error);
		}
		renderSimulatorControls();
	}

	function renderSimulatorControls() {
		const attack = state.simulatorStatus.attack_sim || {};
		const legacy = state.simulatorStatus.legacy_api || {};
		const attackRunning = Boolean(attack.running);
		const legacyOnline = Boolean(legacy.online || legacy.running);
		ui.simulatorSummaryStatus.textContent = `${legacyOnline ? "Legacy online" : "Legacy offline"} · ${attackRunning ? "Attack simulation running" : "Attack simulation stopped"}`;
		setLauncherBadge(ui.legacyLaunchStatus, legacyOnline ? "Online" : "Offline", legacyOnline ? "online" : "offline");
		setLauncherBadge(ui.attackLaunchStatus, attackRunning ? "Running" : "Stopped", attackRunning ? "online" : "offline");
		ui.legacyStartButton.disabled = state.simulatorPending || legacyOnline;
		ui.legacyStopButton.disabled = state.simulatorPending || !legacy.managed;
		ui.attackStartButton.disabled = state.simulatorPending || attackRunning || state.selectedAttackTypes.size === 0;
		ui.attackStopButton.disabled = state.simulatorPending || !attackRunning;
		ui.attackTypeOptions.querySelectorAll("input[name='attack-type']").forEach((checkbox) => {
			const isRunning = (attack.attack_types || []).includes(checkbox.value);
			checkbox.checked = isRunning || state.selectedAttackTypes.has(checkbox.value);
			checkbox.disabled = state.simulatorPending || isRunning;
		});
		ui.legacyLaunchMessage.textContent = legacyOnline
			? (legacy.managed ? "Legacy API is running under dashboard control." : "Legacy API is already online from another terminal.")
			: (ui.legacyLaunchMessage.dataset.message || "Start the ASP.NET source here or from its terminal.");
		ui.attackLaunchMessage.textContent = attackRunning
			? `Running: ${(attack.attack_types || []).join(", ")}. Stop the simulation to change the selection.`
			: (ui.attackLaunchMessage.dataset.message || "Select one or more attack types, then start the simulation.");
	}

	function setLauncherBadge(element, label, className) {
		element.textContent = label;
		element.className = `health-badge health-${className}`;
	}

	async function handleSimulatorRequest(url, body, kind) {
		if (state.simulatorPending) return;
		state.simulatorPending = true;
		const messageElement = kind === "legacy" ? ui.legacyLaunchMessage : ui.attackLaunchMessage;
		messageElement.dataset.message = "Working…";
		renderSimulatorControls();
		try {
			const response = await fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json", Accept: "application/json" },
				body: JSON.stringify(body)
			});
			let payload = {};
			try {
				payload = await response.json();
			} catch {
				if (response.status === 404) {
					throw new Error("This bridge process does not provide simulator controls. Restart the bridge from this project checkout.");
				}
				throw new Error(`Simulator request failed with status ${response.status}.`);
			}
			if (!response.ok || !payload.success) throw new Error(payload.message || `Simulator request failed with status ${response.status}.`);
			messageElement.dataset.message = payload.message || "Simulator state updated.";
			await refreshSimulatorStatus();
		} catch (error) {
			messageElement.dataset.message = error instanceof Error ? error.message : "Simulator action failed.";
		} finally {
			state.simulatorPending = false;
			renderSimulatorControls();
		}
	}

	async function handleAutoMitigationToggle() {
		const enabled = ui.autoMitigateToggle.checked;
		ui.autoMitigateToggle.disabled = true;
		try {
			const response = await fetch("/api/automation/auto-mitigate", {
				method: "POST",
				headers: { "Content-Type": "application/json", Accept: "application/json" },
				body: JSON.stringify({ enabled })
			});
			const payload = await response.json();
			if (!response.ok) throw new Error(payload.detail || "Could not update auto-mitigation.");
			state.autoMitigation = payload;
		} catch (error) {
			ui.autoMitigateToggle.checked = !enabled;
			state.autoMitigation = { ...state.autoMitigation, message: error instanceof Error ? error.message : "Could not update auto-mitigation." };
		} finally {
			ui.autoMitigateToggle.disabled = false;
			renderAutoMitigation();
		}
	}

	function renderAutoMitigation() {
		const automation = state.autoMitigation || {};
		ui.autoMitigateToggle.checked = Boolean(automation.enabled);
		ui.autoMitigateMessage.textContent = automation.message || (automation.enabled
			? "On · at 200 buffered events, resolve up to five oldest critical alerts"
			: "Off · alerts remain until manually mitigated");
	}

	async function loadInvestigationHistory(reset) {
		if (state.historyLoading) return;
		state.historyLoading = true;
		ui.historyError.textContent = "";
		ui.historyLoadMore.disabled = true;
		try {
			if (reset) {
				state.historyOffset = 0;
				state.historyEvents = [];
			}
			const days = Number(ui.historyDays.value || 30);
			const [summary, response] = await Promise.all([
				fetchJson(`/api/history/summary?days=${days}`),
				fetchJson(`/api/history/events?limit=100&offset=${state.historyOffset}`)
			]);
			state.historySummary = summary;
			state.historyEvents = state.historyEvents.concat(response.events || []);
			state.historyOffset = state.historyEvents.length;
			renderInvestigationHistory();
		} catch (error) {
			ui.historyError.textContent = error instanceof Error ? error.message : "Could not load investigation history.";
		} finally {
			state.historyLoading = false;
			ui.historyLoadMore.disabled = false;
		}
	}

	function renderInvestigationHistory() {
		const summary = state.historySummary;
		if (!summary) return;
		ui.historySummaryMeta.textContent = `${summary.total_events} archived events · last ${summary.days} days in charts`;
		renderHistoryTimeline(summary.timeline || []);
		renderHistorySeverity(summary.by_risk || []);
		renderDistributionRows(ui.historyCategoryChart, (summary.by_category || []).map((row) => ({ label: titleCase(row.label), count: row.count, className: distributionClassForCategory(row.label) })));
		renderDistributionRows(ui.historySourceChart, (summary.by_source || []).map((row) => ({ label: titleCase(row.label), count: row.count, className: String(row.label).includes("attack") ? "high" : "medium" })));
		if (!state.historyEvents.length) {
			ui.historyEventList.innerHTML = '<p class="feed-empty">No archived investigation records yet.</p>';
		} else {
			ui.historyEventList.innerHTML = state.historyEvents.map((item) => `
				<article class="history-event-row">
					<div><strong>${escapeHtml(item.title || "Security event")}</strong><span>${escapeHtml(item.id)} · ${escapeHtml(titleCase(item.source_system))} · ${escapeHtml(item.origin || "unknown origin")}</span></div>
					<div><span class="history-event-risk risk-${escapeHtml(item.risk_level)}">${escapeHtml(titleCase(item.risk_level))} · ${Number(item.risk_score) || 0}</span><time>${escapeHtml(formatDateTime(item.observed_at))}</time></div>
				</article>`).join("");
		}
		ui.historyLoadMore.hidden = state.historyEvents.length >= Number(summary.total_events || 0);
	}

	function renderHistoryTimeline(points) {
		if (!points.length) {
			ui.historyTimeline.innerHTML = '<p class="feed-empty">No events in this chart window.</p>';
			return;
		}
		const max = Math.max(...points.map((point) => Number(point.count) || 0), 1);
		ui.historyTimeline.innerHTML = points.slice(-48).map((point) => {
			const height = Math.max(4, (Number(point.count) / max) * 100);
			const label = String(point.hour || "").slice(5, 13).replace("T", " ");
			return `<div class="history-time-column" title="${escapeHtml(label)} · ${Number(point.count)} events"><span style="height:${height}%"></span><small>${escapeHtml(label.slice(-5))}</small></div>`;
		}).join("");
	}

	function renderHistorySeverity(entries) {
		const colors = { critical: "#f1676b", high: "#f6a45b", medium: "#efd06d", low: "#4bc6a6" };
		const total = entries.reduce((sum, row) => sum + Number(row.count || 0), 0);
		if (!total) {
			ui.historySeverityDonut.style.background = "var(--border)";
			ui.historySeverityLegend.innerHTML = '<p class="feed-empty">No severity data yet.</p>';
			return;
		}
		let position = 0;
		const stops = entries.map((row) => {
			const start = position;
			position += (Number(row.count) / total) * 100;
			return `${colors[row.label] || "#8496ae"} ${start}% ${position}%`;
		});
		ui.historySeverityDonut.style.background = `conic-gradient(${stops.join(",")})`;
		ui.historySeverityDonut.innerHTML = `<span>${total}<small>events</small></span>`;
		ui.historySeverityLegend.innerHTML = entries.map((row) => `<div><i style="background:${colors[row.label] || "#8496ae"}"></i><span>${escapeHtml(titleCase(row.label))}</span><strong>${Number(row.count)}</strong></div>`).join("");
	}

	function scheduleReconnect() {
		state.reconnectAttempt += 1;
		const delay = Math.min(reconnectBaseDelay * state.reconnectAttempt, 8000);
		window.setTimeout(connectEventStream, delay);
	}

	function parseEventData(event) {
		try {
			return JSON.parse(event.data);
		} catch (error) {
			console.warn("Failed to parse SSE payload.", error);
			return null;
		}
	}

	function ingestState(payload) {
		state.events = Array.isArray(payload.events) ? payload.events.slice() : state.events;
		state.sourceHealth = payload.source_health || state.sourceHealth;
		state.globalRiskScore = Number(payload.global_risk_score || 0);
		state.globalThreatLevel = (payload.global_threat_level || "low").toLowerCase();
		state.activeEventCount = Number(payload.active_event_count || 0);
		if (payload.auto_mitigation) {
			state.autoMitigation = payload.auto_mitigation;
			ui.autoMitigateToggle.checked = Boolean(payload.auto_mitigation.enabled);
		}
		state.lastUpdatedAt = newestTimestampFromEvents(state.events) || state.lastUpdatedAt || new Date().toISOString();
		if (!state.selectedEventId || !state.events.some((eventItem) => eventItem.id === state.selectedEventId)) {
			const nextSelection = choosePriorityEvent(state.events);
			state.selectedEventId = nextSelection ? nextSelection.id : null;
		}
		reconcileContainmentLifecycle();
	}

	function applyHealthResponse(payload) {
		state.sourceHealth = Object.assign({}, state.sourceHealth, payload.sources || {});
		reconcileContainmentLifecycle();
	}

	function reconcileContainmentLifecycle() {
		if (getAttackSimStatus() !== "mitigated" && !state.mitigationPending && state.mitigationResult?.success) {
			state.mitigationResult = null;
		}
	}

	function upsertEvent(eventPayload, isRealtime) {
		const existingIndex = state.events.findIndex((eventItem) => eventItem.id === eventPayload.id);
		if (existingIndex >= 0) {
			state.events.splice(existingIndex, 1);
		}

		state.events.unshift(eventPayload);
		state.events = state.events.slice(0, Math.max(state.events.length, 60));
		if (isRealtime) {
			state.lastUpdatedAt = eventPayload.ingested_at || eventPayload.observed_at || new Date().toISOString();
		}
	}

	function updateDerivedMetrics() {
		const metrics = computeDerivedMetrics(state.events, state.sourceHealth);
		state.activeEventCount = metrics.activeThreatCount;
		state.globalRiskScore = Math.max(state.globalRiskScore, metrics.maxRiskScore);
		if (riskWeight(metrics.maxRiskLevel) > riskWeight(state.globalThreatLevel)) {
			state.globalThreatLevel = metrics.maxRiskLevel;
		}
	}

	function setBridgeStatus(status) {
		state.bridgeStatus = status;
		const label = { connecting: "Connecting", online: "Streaming", reconnecting: "Reconnecting" }[status] || "Unknown";
		ui.connectionStatus.textContent = label;
		ui.healthBridge.textContent = label;
		ui.healthBridge.className = `health-badge health-${status}`;
		ui.body.classList.toggle("bridge-reconnecting", status !== "online");
	}

	function renderAll(options = {}) {
		renderAlertBanner();
		renderGauge();
		renderMetrics();
		renderIncident();
		renderContainment();
		renderHealth();
		renderSimulatorControls();
		renderAutoMitigation();
		renderOperatorQueue(options.highlightEventId || null);
		renderAnalytics();
		renderAiBrief();
		renderMeta();
	}

	function renderOperatorQueue(highlightEventId) {
		renderFeed(highlightEventId);
		renderMeta();
	}

	function renderAlertBanner() {
		const currentThreat = getSelectedEvent() || choosePriorityEvent(state.events);
		const simStatus = getAttackSimStatus();
		const unresolvedCount = state.events.filter((eventItem) => String(eventItem.status || "").toLowerCase() !== "mitigated").length;

		if (state.mitigationPending) {
			ui.alertBanner.hidden = false;
			ui.alertBannerKicker.textContent = "Escalation";
			ui.alertBannerTitle.textContent = "Mitigation in progress";
			ui.alertBannerCopy.textContent = "The analytics bridge is issuing the containment action against the live simulator process.";
			return;
		}

		if (unresolvedCount === 0 && (simStatus === "mitigated" || state.mitigationResult?.success)) {
			ui.alertBanner.hidden = false;
			ui.alertBannerKicker.textContent = "Escalation";
			ui.alertBannerTitle.textContent = "All current attacks mitigated";
			ui.alertBannerCopy.textContent = state.mitigationResult?.message || "Buffered alerts from both sources are marked mitigated. Check source health for simulator status.";
			return;
		}

		if (!currentThreat) {
			ui.alertBanner.hidden = true;
			return;
		}

		const level = normalizeRiskLevel(currentThreat.risk_level);
		if (!["high", "critical"].includes(level)) {
			ui.alertBanner.hidden = true;
			return;
		}

		ui.alertBanner.hidden = false;
		ui.alertBannerKicker.textContent = "Escalation";
		ui.alertBannerTitle.textContent = level === "critical" ? "Critical activity detected" : "High-risk activity detected";
		ui.alertBannerCopy.textContent = `${currentThreat.title} from ${currentThreat.origin} is the current priority. ${currentThreat.recommended_action}`;
		ui.alertBanner.classList.remove("critical-pulse");
		void ui.alertBanner.offsetWidth;
		ui.alertBanner.classList.add("critical-pulse");
	}

	function renderMeta() {
		ui.lastUpdateLabel.textContent = state.lastUpdatedAt ? formatDateTime(state.lastUpdatedAt) : "Waiting for telemetry";
		const visibleEvents = getVisibleEvents();
		ui.feedSummary.textContent = `${visibleEvents.length} of ${state.events.length} recent events in the operator queue`;
	}

	function renderGauge() {
		const score = clampNumber(state.globalRiskScore, 0, 100);
		const level = normalizeRiskLevel(state.globalThreatLevel);
		const dashOffset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
		ui.gaugeRing.style.strokeDashoffset = String(dashOffset);
		ui.globalRiskScore.textContent = String(score);
		ui.globalRiskLevel.textContent = titleCase(level);
		ui.globalRiskLevel.className = `risk-pill risk-${level}`;
		ui.globalPostureCopy.textContent = postureCopy(level, score);
		ui.postureIndicator.textContent = postureIndicatorCopy(level);
		ui.body.classList.remove("theme-low", "theme-medium", "theme-high", "theme-critical");
		ui.body.classList.add(`theme-${level}`);
	}

	function renderMetrics() {
		const metrics = computeDerivedMetrics(state.events, state.sourceHealth);
		trackMetricHistory(metrics);

		renderMetricCard(ui.activeThreatCount, ui.activeThreatTrend, ui.activeThreatDelta, ui.activeThreatSpark, String(metrics.activeThreatCount), summarizeWindowChange(state.events, isActiveThreat), buildCountSeries(state.events, isActiveThreat));
		renderMetricCard(ui.eventCount, ui.eventCountTrend, ui.eventCountDelta, ui.eventCountSpark, String(metrics.recentEventCount), summarizeWindowChange(state.events, () => true), buildCountSeries(state.events, () => true));
		renderMetricCard(ui.elevatedEventCount, ui.elevatedEventTrend, ui.elevatedEventDelta, ui.elevatedEventSpark, String(metrics.elevatedEventCount), summarizeWindowChange(state.events, isElevatedEvent), buildCountSeries(state.events, isElevatedEvent));
		renderMetricCard(ui.healthySourceCount, ui.healthySourceTrend, ui.healthySourceDelta, ui.healthySourceSpark, `${metrics.healthySources}/3`, summarizeHealthHistory(state.metricHistory.healthy), state.metricHistory.healthy.map((entry) => entry.value));
	}

	function renderMetricCard(valueElement, trendElement, deltaElement, sparkElement, displayValue, summary, series) {
		valueElement.textContent = displayValue;
		trendElement.textContent = summary.label;
		deltaElement.textContent = summary.detail;
		renderSparkline(sparkElement, series, summary.color);
	}

	function renderFeed(highlightEventId) {
		const visibleEvents = getVisibleEvents();
		if (!visibleEvents.length) {
			ui.feedList.innerHTML = '<div class="feed-empty">No recent telemetry matches the current feed filters.</div>';
			return;
		}

		const fragment = document.createDocumentFragment();
		visibleEvents.forEach((eventItem) => {
			const level = normalizeRiskLevel(eventItem.risk_level);
			const isMitigated = String(eventItem.status || "").toLowerCase() === "mitigated";
			const mitigationPending = state.mitigationPending || state.eventMitigationsPending.has(eventItem.id);
			const article = document.createElement("article");
			article.className = `feed-item ${level === "high" || level === "critical" ? "elevated" : ""} ${level === "critical" ? "critical" : ""}`.trim();
			article.tabIndex = 0;
			article.role = "listitem";
			if (state.selectedEventId === eventItem.id) {
				article.classList.add("selected");
			}
			if (highlightEventId === eventItem.id) {
				article.classList.add("new");
			}

			article.innerHTML = `
				<span class="feed-severity ${level}" aria-hidden="true"></span>
				<div class="feed-main">
					<div class="feed-title-row">
						<h3>${escapeHtml(eventItem.title)}</h3>
						<div class="feed-tags">
							<span class="risk-pill risk-${level}">${titleCase(level)}</span>
							<span class="incident-source-chip">${escapeHtml(labelForSourceSystem(eventItem.source_system))}</span>
						</div>
					</div>
					<div class="feed-meta-row">
						<div>
							<div class="feed-origin">${escapeHtml(eventItem.origin)}</div>
							<div class="feed-meta">${escapeHtml(formatClock(eventItem.observed_at))} · ${escapeHtml(titleCase(eventItem.status || "active"))}</div>
						</div>
						<div class="feed-meta">${escapeHtml(eventItem.summary)}</div>
					</div>
				</div>
				<div class="feed-score-block">
					<div class="feed-score-label">Risk</div>
					<div class="feed-score">${escapeHtml(String(eventItem.risk_score))}</div>
					<button class="event-mitigate-button ${isMitigated ? "resolved" : ""}" type="button" data-mitigate-event="${escapeHtml(eventItem.id)}" title="Mark this alert mitigated. This does not stop or change its source system." ${isMitigated || mitigationPending ? "disabled" : ""}>${isMitigated ? "Mitigated" : mitigationPending ? "Updating…" : "Mitigate"}</button>
				</div>
			`;
			article.querySelector("[data-mitigate-event]").addEventListener("click", (clickEvent) => {
				clickEvent.stopPropagation();
				handleEventMitigation(eventItem.id);
			});

			article.addEventListener("click", () => {
				state.selectedEventId = eventItem.id;
				renderAll();
			});
			article.addEventListener("keydown", (keyboardEvent) => {
				if (keyboardEvent.target.closest("button")) return;
				if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
					keyboardEvent.preventDefault();
					state.selectedEventId = eventItem.id;
					renderAll();
				}
			});
			fragment.appendChild(article);
		});

		ui.feedList.replaceChildren(fragment);
	}

	function renderIncident() {
		const selected = getSelectedEvent();
		const operatorState = deriveOperatorState(selected);
		ui.incidentOperatorState.textContent = operatorState.label;
		ui.incidentOperatorState.className = operatorState.className;

		if (!selected) {
			ui.incidentEmpty.hidden = false;
			ui.incidentContent.hidden = true;
			ui.priorityActionTitle.textContent = "Waiting for prioritized incident";
			ui.priorityActionMeta.textContent = "Risk - · -";
			ui.priorityActionResponse.textContent = "Recommended response will appear when an incident is available.";
			return;
		}

		ui.incidentEmpty.hidden = true;
		ui.incidentContent.hidden = false;
		ui.incidentTitle.textContent = selected.title;
		ui.priorityActionTitle.textContent = selected.title;
		ui.priorityActionMeta.textContent = `Risk ${selected.risk_score} · ${selected.origin}`;
		ui.priorityActionResponse.textContent = selected.recommended_action;
		ui.incidentLevel.textContent = titleCase(normalizeRiskLevel(selected.risk_level));
		ui.incidentLevel.className = `risk-pill risk-${normalizeRiskLevel(selected.risk_level)}`;
		ui.incidentSourceChip.textContent = labelForSourceSystem(selected.source_system);
		ui.incidentSummary.textContent = selected.summary;
		ui.incidentScore.textContent = String(selected.risk_score);
		ui.incidentOrigin.textContent = selected.origin;
		ui.incidentSource.textContent = labelForSourceSystem(selected.source_system);
		ui.incidentStatus.textContent = titleCase(selected.status || "active");
		ui.incidentObserved.textContent = formatDateTime(selected.observed_at);
		ui.incidentAction.textContent = selected.recommended_action;
		ui.incidentId.textContent = selected.id;
		ui.incidentSourceSystem.textContent = labelForSourceSystem(selected.source_system);
		ui.incidentSourceType.textContent = titleCase(selected.source_type || "unknown");
		ui.incidentCategory.textContent = titleCase(selected.category || "unknown");
		ui.incidentObservedDetail.textContent = formatDateTime(selected.observed_at);
		ui.incidentIngested.textContent = formatDateTime(selected.ingested_at);
		ui.incidentRawSeverity.textContent = selected.raw_severity == null ? "Not provided" : String(selected.raw_severity);
		ui.incidentRiskScoreDetail.textContent = `${selected.risk_score} (${titleCase(selected.risk_level)})`;
		ui.incidentStatusDetail.textContent = titleCase(selected.status || "active");
		ui.incidentRaw.textContent = JSON.stringify(selected.raw, null, 2);
	}

	function renderContainment() {
		const simStatus = getAttackSimStatus();
		const hasAttackSimTelemetry = state.events.some((eventItem) => eventItem.source_system === "attack_sim");
		const unresolvedEventCount = state.events.filter((eventItem) => String(eventItem.status || "").toLowerCase() !== "mitigated").length;
		const canMitigate = unresolvedEventCount > 0 || simStatus === "online" || simStatus === "waiting" || (simStatus === "unknown" && hasAttackSimTelemetry);

		if (state.mitigationPending) {
			ui.mitigateButton.disabled = true;
			ui.mitigateButton.textContent = "Mitigating all…";
			ui.mitigateButton.className = "containment-button danger";
			ui.containmentStatus.hidden = false;
			ui.containmentTitle.textContent = "Mitigating all alerts";
			ui.containmentMessage.textContent = "The bridge is stopping the simulator and updating unresolved alerts from both sources.";
			return;
		}

		if (unresolvedEventCount === 0 && (simStatus === "mitigated" || state.mitigationResult?.success)) {
			ui.mitigateButton.disabled = true;
			ui.mitigateButton.textContent = "All Attacks Mitigated";
			ui.mitigateButton.className = "containment-button success";
			ui.containmentStatus.hidden = false;
			ui.containmentTitle.textContent = "All current alerts mitigated";
			ui.containmentMessage.textContent = state.mitigationResult?.message || "All buffered alert records are marked mitigated. Check source health for simulator status.";
			ui.containmentStatus.classList.remove("pulse");
			void ui.containmentStatus.offsetWidth;
			ui.containmentStatus.classList.add("pulse");
			return;
		}

		ui.mitigateButton.disabled = !canMitigate || state.eventMitigationsPending.size > 0;
		ui.mitigateButton.textContent = "Mitigate All";
		ui.mitigateButton.className = `containment-button danger ${state.mitigationResult && !state.mitigationResult.success ? "error" : ""}`.trim();
		ui.containmentStatus.hidden = !state.eventMitigationError && (!state.mitigationResult || state.mitigationResult.success);
		if (state.eventMitigationError) {
			ui.containmentTitle.textContent = "Alert mitigation failed";
			ui.containmentMessage.textContent = state.eventMitigationError;
		} else if (state.mitigationResult && !state.mitigationResult.success) {
			ui.containmentTitle.textContent = "Mitigation failed";
			ui.containmentMessage.textContent = state.mitigationResult.message || "The all-alert mitigation action failed.";
		}
	}

	function renderHealth() {
		renderHealthBadge(ui.healthLegacy, state.sourceHealth.legacy_api);
		renderHealthBadge(ui.healthSim, state.sourceHealth.attack_sim);
	}

	function renderHealthBadge(element, source) {
		if (!source) {
			element.textContent = "Unknown";
			element.className = "health-badge health-unknown";
			return;
		}

		const normalizedStatus = normalizeHealthStatus(source.status, source.available);
		element.textContent = normalizedStatus.label;
		element.className = `health-badge health-${normalizedStatus.className}`;
	}

	function renderAnalytics() {
		renderTimeline();
		renderDistribution();
		renderSourceActivity();
	}

	function renderTimeline() {
		const recent = state.events.slice(0, MAX_TIMELINE_POINTS).reverse();
		if (!recent.length) {
			ui.timelineChart.innerHTML = '<text class="timeline-label" x="18" y="88">Waiting for activity data</text>';
			ui.timelineSummary.textContent = "Waiting for telemetry";
			ui.timelineDetail.textContent = "No threat activity in the current window";
			return;
		}

		const width = 640;
		const height = 170;
		const padding = { top: 18, right: 16, bottom: 28, left: 18 };
		const chartWidth = width - padding.left - padding.right;
		const chartHeight = height - padding.top - padding.bottom;
		const values = recent.map((eventItem) => clampNumber(Number(eventItem.risk_score || 0), 0, 100));
		const stepX = recent.length > 1 ? chartWidth / (recent.length - 1) : chartWidth;
		const points = recent.map((eventItem, index) => {
			const x = padding.left + index * stepX;
			const y = padding.top + chartHeight - (values[index] / 100) * chartHeight;
			return { x, y, level: normalizeRiskLevel(eventItem.risk_level), label: formatClock(eventItem.observed_at) };
		});
		const linePath = points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ");
		const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(2)},${(height - padding.bottom).toFixed(2)} L ${points[0].x.toFixed(2)},${(height - padding.bottom).toFixed(2)} Z`;
		const gridLines = [0, 25, 50, 75, 100].map((value) => {
			const y = padding.top + chartHeight - (value / 100) * chartHeight;
			return `<line class="timeline-grid-line" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"></line>`;
		}).join("");
		const circles = points.map((point) => `<circle class="timeline-point" cx="${point.x}" cy="${point.y}" r="4.5" fill="${colorForRisk(point.level)}"></circle>`).join("");
		const labels = [points[0], points[points.length - 1]].map((point) => `<text class="timeline-label" x="${point.x}" y="${height - 10}" text-anchor="middle">${escapeHtml(point.label)}</text>`).join("");
		ui.timelineChart.innerHTML = `${gridLines}<path class="timeline-area" d="${areaPath}"></path><path class="timeline-line" d="${linePath}"></path>${circles}${labels}`;
		const peakLevel = normalizeRiskLevel(choosePriorityEvent(recent)?.risk_level || "low");
		ui.timelineSummary.textContent = `${recent.length} detections in the current timeline`;
		ui.timelineDetail.textContent = `${titleCase(peakLevel)} is the peak severity in view`;
	}

	function renderDistribution() {
		const entries = Object.entries(countBy(state.events, (eventItem) => eventItem.category || "unknown")).sort((left, right) => right[1] - left[1]);
		if (!entries.length) {
			ui.distributionChart.innerHTML = '<div class="feed-empty">Awaiting categorized telemetry.</div>';
			ui.distributionSummary.textContent = "Awaiting telemetry";
			return;
		}
		renderDistributionRows(ui.distributionChart, entries.map(([label, count]) => ({ label: titleCase(label), count, className: distributionClassForCategory(label) })));
		ui.distributionSummary.textContent = `${titleCase(entries[0][0])} is the most active category`;
	}

	function renderSourceActivity() {
		const entries = Object.entries(countBy(state.events, (eventItem) => labelForSourceSystem(eventItem.source_system))).sort((left, right) => right[1] - left[1]);
		if (!entries.length) {
			ui.sourceActivityChart.innerHTML = '<div class="feed-empty">Awaiting source telemetry.</div>';
			ui.sourceActivitySummary.textContent = "Awaiting telemetry";
			return;
		}
		renderDistributionRows(ui.sourceActivityChart, entries.map(([label, count]) => ({ label, count, className: label.includes("Attack") ? "high" : "medium" })));
		ui.sourceActivitySummary.textContent = entries.map(([label, count]) => `${label}: ${count}`).join(" · ");
	}

	function renderDistributionRows(container, rows) {
		const maxCount = Math.max(...rows.map((row) => row.count), 1);
		container.innerHTML = rows.map((row) => `
			<div class="distribution-chart-row">
				<div class="distribution-topline">
					<span>${escapeHtml(row.label)}</span>
					<strong>${row.count}</strong>
				</div>
				<div class="distribution-bar-track">
					<div class="distribution-bar-fill ${row.className}" style="width: ${(row.count / maxCount) * 100}%"></div>
				</div>
			</div>
		`).join("");
	}

	function deriveOperatorState(selected) {
		if (state.mitigationPending) {
			return { label: "Mitigating", className: "mini-status health-waiting" };
		}
		if (selected && String(selected.status || "").toLowerCase() === "mitigated") {
			return { label: "Mitigated", className: "mini-status health-mitigated" };
		}
		if (!selected) {
			return { label: "Waiting", className: "mini-status" };
		}
		const level = normalizeRiskLevel(selected.risk_level);
		if (level === "critical") {
			return { label: "Critical", className: "mini-status risk-critical" };
		}
		if (level === "high") {
			return { label: "High", className: "mini-status risk-high" };
		}
		if (getAttackSimStatus() === "online") {
			return { label: "Active", className: "mini-status health-online" };
		}
		return { label: "Waiting", className: "mini-status" };
	}

	function getSelectedEvent() {
		return state.events.find((eventItem) => eventItem.id === state.selectedEventId) || choosePriorityEvent(state.events);
	}

	function choosePriorityEvent(events) {
		const unresolvedEvents = events.filter((eventItem) => String(eventItem.status || "").toLowerCase() !== "mitigated");
		if (!unresolvedEvents.length) {
			return null;
		}
		return unresolvedEvents.slice().sort((left, right) => priorityWeight(right) - priorityWeight(left))[0];
	}

	function autoSelectCurrentThreat(newEventId) {
		const currentSelection = getSelectedEvent();
		const candidate = state.events.find((eventItem) => eventItem.id === newEventId);
		if (!candidate) {
			return;
		}
		if (!currentSelection || String(currentSelection.status || "").toLowerCase() === "mitigated" || priorityWeight(candidate) >= priorityWeight(currentSelection)) {
			state.selectedEventId = candidate.id;
		}
	}

	function computeDerivedMetrics(events, sourceHealth) {
		const elevatedEventCount = events.filter(isElevatedEvent).length;
		const activeThreatCount = state.activeEventCount > 0 ? state.activeEventCount : events.filter(isActiveThreat).length;
		const healthySources = [
			state.bridgeStatus === "online",
			Boolean(sourceHealth.legacy_api && sourceHealth.legacy_api.available),
			Boolean(sourceHealth.attack_sim && sourceHealth.attack_sim.available)
		].filter(Boolean).length;
		const maxRiskEvent = choosePriorityEvent(events);
		return {
			activeThreatCount,
			recentEventCount: events.length,
			elevatedEventCount,
			healthySources,
			maxRiskScore: maxRiskEvent ? Number(maxRiskEvent.risk_score || 0) : 0,
			maxRiskLevel: maxRiskEvent ? normalizeRiskLevel(maxRiskEvent.risk_level) : "low"
		};
	}

	function trackMetricHistory(metrics) {
		const signature = `${metrics.activeThreatCount}|${metrics.recentEventCount}|${metrics.elevatedEventCount}|${metrics.healthySources}`;
		if (signature === state.lastMetricsSignature) {
			return;
		}
		state.lastMetricsSignature = signature;
		pushMetricSample(state.metricHistory.active, metrics.activeThreatCount);
		pushMetricSample(state.metricHistory.recent, metrics.recentEventCount);
		pushMetricSample(state.metricHistory.elevated, metrics.elevatedEventCount);
		pushMetricSample(state.metricHistory.healthy, metrics.healthySources);
	}

	function pushMetricSample(history, value) {
		history.push({ at: Date.now(), value });
		while (history.length > METRIC_HISTORY_LIMIT) {
			history.shift();
		}
	}

	function summarizeWindowChange(events, predicate) {
		const latestTimestamp = newestTimestampValue(events);
		if (latestTimestamp == null) {
			return { label: "Steady", detail: "No recent change", color: "#5bb0ff" };
		}
		const currentStart = latestTimestamp - TREND_WINDOW_MS;
		const previousStart = latestTimestamp - (TREND_WINDOW_MS * 2);
		let current = 0;
		let previous = 0;
		events.forEach((eventItem) => {
			const timestamp = eventTimestampValue(eventItem);
			if (timestamp == null || !predicate(eventItem)) {
				return;
			}
			if (timestamp > currentStart) {
				current += 1;
			} else if (timestamp > previousStart) {
				previous += 1;
			}
		});
		const difference = current - previous;
		if (difference > 0) {
			return { label: "Rising", detail: `+${difference} vs prior minute`, color: "#ff9447" };
		}
		if (difference < 0) {
			return { label: "Cooling", detail: `${difference} vs prior minute`, color: "#52d6a8" };
		}
		return { label: "Steady", detail: "No change vs prior minute", color: "#5bb0ff" };
	}

	function summarizeHealthHistory(history) {
		if (history.length < 2) {
			return { label: "Steady", detail: "Awaiting source updates", color: "#5bb0ff" };
		}
		const latest = history[history.length - 1].value;
		const previous = history[Math.max(history.length - 2, 0)].value;
		const difference = latest - previous;
		if (difference > 0) {
			return { label: "Recovered", detail: `+${difference} source recovered`, color: "#52d6a8" };
		}
		if (difference < 0) {
			return { label: "Degraded", detail: `${difference} source vs prior update`, color: "#ff5f6d" };
		}
		return { label: "Steady", detail: "No source change", color: "#5bb0ff" };
	}

	function buildCountSeries(events, predicate) {
		const latestTimestamp = newestTimestampValue(events);
		if (latestTimestamp == null) {
			return [];
		}
		const binWidth = SPARKLINE_WINDOW_MS / SPARKLINE_BINS;
		const bins = new Array(SPARKLINE_BINS).fill(0);
		events.forEach((eventItem) => {
			const timestamp = eventTimestampValue(eventItem);
			if (timestamp == null || !predicate(eventItem)) {
				return;
			}
			const age = latestTimestamp - timestamp;
			if (age < 0 || age > SPARKLINE_WINDOW_MS) {
				return;
			}
			const binIndex = SPARKLINE_BINS - 1 - Math.min(SPARKLINE_BINS - 1, Math.floor(age / binWidth));
			bins[binIndex] += 1;
		});
		return bins;
	}

	function renderSparkline(element, series, color) {
		if (!series.length) {
			element.innerHTML = '<path d="M0,16 L120,16" stroke="rgba(84, 168, 255, 0.24)" stroke-width="2" fill="none"></path>';
			return;
		}
		const width = 120;
		const height = 32;
		const maxValue = Math.max(...series, 1);
		const stepX = series.length > 1 ? width / (series.length - 1) : width;
		const path = series.map((value, index) => {
			const x = index * stepX;
			const y = height - ((value / maxValue) * (height - 4)) - 2;
			return `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
		}).join(" ");
		element.innerHTML = `<path d="${path}" stroke="${color}" stroke-width="2.2" fill="none" stroke-linecap="round"></path>`;
	}

	function getVisibleEvents() {
		const query = state.feed.search.trim().toLowerCase();
		const filtered = state.events.filter((eventItem) => {
			const level = normalizeRiskLevel(eventItem.risk_level);
			const severityMatch = state.feed.severity === "all" ? true : level === state.feed.severity;
			const sourceMatch = state.feed.source === "all" ? true : eventItem.source_system === state.feed.source;
			const searchHaystack = [eventItem.title, eventItem.origin, eventItem.source_system, eventItem.source_type, labelForSourceSystem(eventItem.source_system)].join(" ").toLowerCase();
			const searchMatch = !query || searchHaystack.includes(query);
			return severityMatch && sourceMatch && searchMatch;
		});
		filtered.sort((left, right) => state.feed.sort === "highest-risk" ? priorityWeight(right) - priorityWeight(left) : eventTimestampValue(right) - eventTimestampValue(left));
		return filtered;
	}

	function postureCopy(level, score) {
		const selected = getSelectedEvent();
		const unresolvedCount = state.events.filter((eventItem) => String(eventItem.status || "").toLowerCase() !== "mitigated").length;
		if (unresolvedCount === 0 && (getAttackSimStatus() === "mitigated" || state.mitigationResult?.success)) {
			return "All buffered alerts are mitigated, and posture is easing as recent activity ages out.";
		}
		if (getAttackSimStatus() === "mitigated" && unresolvedCount > 0) {
			return `The simulator is stopped; ${unresolvedCount} buffered alert(s) still need individual review or mitigation.`;
		}
		if (!selected) {
			return "Waiting for normalized telemetry from the analytics bridge.";
		}
		if (level === "critical") {
			return `${selected.title} is driving a critical posture at ${score}. Immediate analyst attention is recommended.`;
		}
		if (level === "high") {
			return `${selected.title} is sustaining elevated risk at ${score}. Review the priority incident and mitigation guidance now.`;
		}
		if (level === "medium") {
			return "The command center is tracking notable activity. The current incident remains contained and observable.";
		}
		return "Threat posture is stable. Monitoring continues across the legacy and simulator sources.";
	}

	function postureIndicatorCopy(level) {
		if (state.mitigationPending) {
			return "Mitigating";
		}
		if (state.events.every((eventItem) => String(eventItem.status || "").toLowerCase() === "mitigated") && (getAttackSimStatus() === "mitigated" || state.mitigationResult?.success)) {
			return "Contained";
		}
		return { low: "Stable", medium: "Elevated", high: "Escalated", critical: "Critical" }[level] || "Stable";
	}

	function getAttackSimStatus() {
		return String(state.sourceHealth.attack_sim?.status || "unknown").toLowerCase();
	}

	function priorityWeight(eventItem) {
		return (Number(eventItem.risk_score || 0) * 1000000) + eventTimestampValue(eventItem);
	}

	function newestTimestampFromEvents(events) {
		return events.length ? (events[0].ingested_at || events[0].observed_at || null) : null;
	}

	function newestTimestampValue(events) {
		const latest = newestTimestampFromEvents(events);
		return latest ? new Date(latest).getTime() : null;
	}

	function eventTimestampValue(eventItem) {
		return new Date(eventItem.ingested_at || eventItem.observed_at || 0).getTime();
	}

	function normalizeRiskLevel(level) {
		const normalized = String(level || "low").toLowerCase();
		return ["low", "medium", "high", "critical"].includes(normalized) ? normalized : "low";
	}

	function normalizeHealthStatus(status, available) {
		const normalized = String(status || "unknown").toLowerCase();
		if (normalized === "online" && available) {
			return { label: "Online", className: "online" };
		}
		if (normalized === "waiting") {
			return { label: "Waiting", className: "waiting" };
		}
		if (normalized === "mitigated") {
			return { label: "Mitigated", className: "mitigated" };
		}
		if (normalized === "offline") {
			return { label: "Offline", className: "offline" };
		}
		if (normalized === "error") {
			return { label: "Error", className: "error" };
		}
		if (normalized === "decode-error") {
			return { label: "Decode error", className: "decode-error" };
		}
		return { label: titleCase(normalized), className: available ? "online" : "unknown" };
	}

	function labelForSourceSystem(sourceSystem) {
		return { attack_sim: "Attack simulator", legacy_api: "Legacy API" }[sourceSystem] || "Analytics bridge";
	}

	function riskWeight(level) {
		return { low: 1, medium: 2, high: 3, critical: 4 }[normalizeRiskLevel(level)] || 1;
	}

	function colorForRisk(level) {
		return { low: "#5bb0ff", medium: "#e9b34c", high: "#ff9447", critical: "#ff596e" }[normalizeRiskLevel(level)];
	}

	function distributionClassForCategory(category) {
		return { identity: "critical", network: "high", application: "medium", endpoint: "high", system: "medium", unknown: "" }[String(category || "unknown").toLowerCase()] || "";
	}

	function countBy(items, selector) {
		return items.reduce((result, item) => {
			const key = selector(item);
			result[key] = (result[key] || 0) + 1;
			return result;
		}, {});
	}

	function isElevatedEvent(eventItem) {
		const level = normalizeRiskLevel(eventItem.risk_level);
		return level === "high" || level === "critical";
	}

	function isActiveThreat(eventItem) {
		return ["active", "failed", "denied"].includes(String(eventItem.status || "").toLowerCase());
	}

	function formatDateTime(value) {
		if (!value) {
			return "Unknown";
		}
		return new Intl.DateTimeFormat(undefined, {
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit"
		}).format(new Date(value));
	}

	function formatClock(value) {
		if (!value) {
			return "Unknown";
		}
		return new Intl.DateTimeFormat(undefined, {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit"
		}).format(new Date(value));
	}

	function titleCase(value) {
		return String(value || "")
			.replace(/[_-]+/g, " ")
			.split(" ")
			.filter(Boolean)
			.map((chunk) => chunk.charAt(0).toUpperCase() + chunk.slice(1))
			.join(" ");
	}

	function clampNumber(value, min, max) {
		return Math.max(min, Math.min(max, Number(value) || 0));
	}

	function escapeHtml(value) {
		return String(value)
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;")
			.replaceAll("'", "&#39;");
	}

	async function handleEventMitigation(eventId) {
		if (state.mitigationPending || state.eventMitigationsPending.has(eventId)) return;
		state.eventMitigationError = null;
		state.eventMitigationsPending.add(eventId);
		renderAll();
		try {
			const response = await fetch(`/api/events/${encodeURIComponent(eventId)}/mitigate`, {
				method: "POST",
				headers: { Accept: "application/json" }
			});
			const payload = await response.json();
			if (!response.ok || !payload.success) {
				throw new Error(payload.detail || payload.message || "Could not mitigate this alert.");
			}
			if (state.selectedEventId === eventId) state.selectedEventId = null;
			ingestState(await fetchJson("/api/state"));
		} catch (error) {
			state.eventMitigationError = error instanceof Error ? error.message : "Could not mitigate this alert.";
		} finally {
			state.eventMitigationsPending.delete(eventId);
			renderAll();
		}
	}

	async function refreshAiStatus() {
		ui.aiRefreshButton.disabled = true;
		ui.aiRefreshButton.textContent = "Checking…";
		try {
			state.aiStatus = await fetchJson("/api/ai/status");
		} catch (error) {
			state.aiStatus = { available: false, model_ready: false, model: "Gemini", message: "Could not reach the AI status endpoint." };
		}
		ui.aiRefreshButton.disabled = false;
		ui.aiRefreshButton.textContent = "Check setup";
		renderAiBrief();
	}

	async function handleAiBriefRequest() {
		if (state.aiPending) return;
		state.aiPending = true;
		state.aiError = null;
		renderAiBrief();
		try {
			const response = await fetch("/api/ai/brief", { method: "POST", headers: { Accept: "application/json" } });
			const payload = await response.json();
			if (!response.ok) {
				throw new Error(payload.detail || "The online analyst could not generate a brief.");
			}
			state.aiBriefResult = payload;
		} catch (error) {
			state.aiError = error instanceof Error ? error.message : "The online analyst could not generate a brief.";
		} finally {
			state.aiPending = false;
			renderAiBrief();
		}
	}

	function renderAiBrief() {
		const status = state.aiStatus;
		const ready = Boolean(status && status.available && status.model_ready);
		ui.aiModelStatus.textContent = !status
			? "Checking API key"
			: ready
				? `${status.provider || "Gemini"} · Key configured`
				: "API key needed";
		ui.aiModelStatus.className = `ai-model-status ${ready ? "ready" : "offline"}`;
		ui.aiGenerateButton.disabled = !ready || state.aiPending;
		ui.aiGenerateButton.textContent = state.aiPending ? "Analyzing telemetry…" : state.aiBriefResult ? "Regenerate brief" : "Generate brief";

		if (state.aiPending) {
			ui.aiAnalystMessage.textContent = "Sending up to 30 normalized recent events to Gemini for an advisory analysis…";
		} else if (state.aiError) {
			ui.aiAnalystMessage.textContent = state.aiError;
		} else if (state.aiBriefResult && isAiBriefStale(state.aiBriefResult)) {
			ui.aiAnalystMessage.textContent = "Telemetry changed since this snapshot. Regenerate the brief for the latest incident picture.";
		} else if (state.aiBriefResult) {
			ui.aiAnalystMessage.textContent = "Brief generated from the current telemetry snapshot. No response action was executed.";
		} else if (status) {
			ui.aiAnalystMessage.textContent = status.message;
		} else {
			ui.aiAnalystMessage.textContent = "Checking Gemini API configuration.";
		}

		ui.aiBrief.hidden = !state.aiBriefResult;
		if (!state.aiBriefResult) return;
		const brief = state.aiBriefResult;
		ui.aiOverallAssessment.textContent = brief.overall_assessment || "No assessment returned.";
		populateTextList(ui.aiKeyFindings, brief.key_findings || [], "No notable findings were returned.");
		populateTextList(ui.aiRecommendedActions, brief.recommended_actions || [], "Continue monitoring and validate findings against source systems.");
		ui.aiCampaignHypotheses.replaceChildren();
		if (!brief.campaign_hypotheses?.length) {
			const empty = document.createElement("p");
			empty.className = "ai-empty-note";
			empty.textContent = "No reliable correlation identified from this event sample.";
			ui.aiCampaignHypotheses.appendChild(empty);
		} else {
			brief.campaign_hypotheses.forEach((hypothesis) => {
				const card = document.createElement("article");
				card.className = "ai-hypothesis";
				const heading = document.createElement("div");
				heading.className = "ai-hypothesis-heading";
				const name = document.createElement("strong");
				name.textContent = hypothesis.name || "Possible pattern";
				const confidence = document.createElement("span");
				confidence.textContent = `${clampNumber(hypothesis.confidence, 0, 100)}% confidence`;
				heading.append(name, confidence);
				const evidence = document.createElement("p");
				evidence.textContent = hypothesis.evidence || "No supporting evidence was returned.";
				const ids = document.createElement("div");
				ids.className = "ai-evidence-ids";
				if (Array.isArray(hypothesis.event_ids) && hypothesis.event_ids.length) {
					const evidenceLabel = document.createElement("span");
					evidenceLabel.textContent = "Evidence";
					ids.appendChild(evidenceLabel);
					hypothesis.event_ids.forEach((eventId) => {
						const evidenceButton = document.createElement("button");
						evidenceButton.type = "button";
						evidenceButton.className = "ai-evidence-link";
						evidenceButton.textContent = eventId;
						evidenceButton.addEventListener("click", () => {
							const eventItem = state.events.find((candidate) => candidate.id === eventId);
							if (!eventItem) return;
							state.selectedEventId = eventId;
							renderAll();
							const feedRow = Array.from(ui.feedList.querySelectorAll("[role='listitem']")).find((row) => row.querySelector("[data-mitigate-event]")?.dataset.mitigateEvent === eventId);
							feedRow?.scrollIntoView({ behavior: "smooth", block: "nearest" });
						});
						ids.appendChild(evidenceButton);
					});
				} else {
					ids.textContent = "No evidence event IDs provided.";
				}
				card.append(heading, evidence, ids);
				ui.aiCampaignHypotheses.appendChild(card);
			});
		}
		ui.aiLimitations.textContent = `Limitations: ${brief.limitations || "Model-generated analysis can be wrong; verify against original telemetry."}`;
		ui.aiBriefMeta.textContent = `${brief.provider || "Gemini"} · ${brief.model || "unknown"} · ${brief.events_analyzed || 0} events · ${formatDateTime(brief.generated_at)}`;
	}

	function populateTextList(element, values, emptyMessage) {
		element.replaceChildren();
		if (!values.length) {
			const item = document.createElement("li");
			item.textContent = emptyMessage;
			element.appendChild(item);
			return;
		}
		values.forEach((value) => {
			const item = document.createElement("li");
			item.textContent = value;
			element.appendChild(item);
		});
	}

	function isAiBriefStale(brief) {
		if (!Array.isArray(brief.snapshot_events)) return false;
		const currentSnapshot = state.events.slice(0, brief.snapshot_events.length).map((eventItem) => ({
			id: eventItem.id,
			status: eventItem.status,
			risk_score: eventItem.risk_score
		}));
		return JSON.stringify(currentSnapshot) !== JSON.stringify(brief.snapshot_events);
	}

	async function handleMitigationRequest() {
		if (state.mitigationPending || state.eventMitigationsPending.size > 0) {
			return;
		}
		state.mitigationPending = true;
		state.mitigationResult = null;
		renderAll();
		try {
			const response = await fetch("/api/control/mitigate", { method: "POST", headers: { Accept: "application/json" } });
			const payload = await response.json();
			state.mitigationResult = payload;
			if (!response.ok || !payload.success) {
				throw new Error(payload.message || "Mitigation request failed.");
			}
			state.selectedEventId = null;
			ingestState(await fetchJson("/api/state"));
			applyHealthResponse(await fetchJson("/api/health"));
			renderAll();
		} catch (error) {
			state.mitigationResult = { success: false, message: error instanceof Error ? error.message : "Mitigation request failed." };
			ui.containmentStatus.hidden = false;
			ui.containmentTitle.textContent = "Mitigation failed";
			ui.containmentMessage.textContent = state.mitigationResult.message;
		} finally {
			state.mitigationPending = false;
			renderAll();
		}
	}

	init();
})();
