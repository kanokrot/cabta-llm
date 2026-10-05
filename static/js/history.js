(function () {
    "use strict";

    var root = document.getElementById("historyPage");
    if (!root) return;

    var DEFAULT_LIMIT = 100;
    var GROUPS = ["malicious", "suspicious", "clean", "failed", "unknown", "in_progress"];
    var TYPES = ["", "ioc", "file", "email"];
    var SORTS = ["date", "score", "verdict", "type", "status"];
    var HISTORY_EXPORT_CAP = 10000;
    var LABELS = {
        malicious: "Malicious",
        suspicious: "Suspicious",
        clean: "Clean",
        failed: "Failed",
        unknown: "Unknown",
        in_progress: "In progress"
    };
    var state = {
        group: "",
        type: "",
        q: "",
        range: "all",
        sort: "date",
        order: "desc",
        limit: DEFAULT_LIMIT,
        offset: 0
    };
    var listController = null;
    var summaryController = new AbortController();
    var requestNumber = 0;
    var searchTimer = null;
    var lastHistoryTotal = 0;
    var exportButton = document.getElementById("historyExport");
    var rowsById = Object.create(null);
    var activeRow = null;
    var previousBodyOverflow = "";
    var drawer = document.getElementById("historyDrawer");
    var drawerBackdrop = document.getElementById("historyDrawerBackdrop");
    var drawerBody = document.getElementById("historyDrawerBody");
    var drawerClose = document.getElementById("historyDrawerClose");

    function groupClass(group) {
        return "history-g-" + (GROUPS.indexOf(group) >= 0 ? group : "unknown");
    }

    function numberValue(value) {
        var result = Number(value);
        return Number.isFinite(result) ? result : 0;
    }

    function text(id, value) {
        var element = document.getElementById(id);
        if (element) element.textContent = String(value);
    }

    function clearSearchTimer() {
        if (searchTimer !== null) {
            window.clearTimeout(searchTimer);
            searchTimer = null;
        }
    }

    function setExportBusy(busy) {
        if (exportButton) exportButton.disabled = busy;
    }

    function showExportLimitError() {
        var error = document.getElementById("historyError");
        error.textContent = "Export is limited to 10,000 analyses. Narrow the filters and try again.";
        error.hidden = false;
    }

    function exportUrl() {
        var params = new URLSearchParams();
        if (state.group) params.set("group", state.group);
        if (state.type) params.set("type", state.type);
        if (state.q) params.set("q", state.q);
        if (state.range !== "all") params.set("range", state.range);
        if (state.sort !== "date") params.set("sort", state.sort);
        if (state.order !== "desc") params.set("order", state.order);
        var query = params.toString();
        return "/api/analysis/history/export" + (query ? "?" + query : "");
    }

    function readUrl() {
        var params = new URLSearchParams(window.location.search);
        var group = params.get("group") || "";
        var type = params.get("type") || "";
        var range = params.get("range") || "all";
        var sort = params.get("sort") || "date";
        var limit = Number(params.get("limit") || DEFAULT_LIMIT);
        var offset = Number(params.get("offset") || 0);

        state.group = GROUPS.indexOf(group) >= 0 ? group : "";
        state.type = TYPES.indexOf(type) >= 0 ? type : "";
        state.q = params.get("q") || "";
        state.range = ["all", "24h", "7d"].indexOf(range) >= 0 ? range : "all";
        state.sort = SORTS.indexOf(sort) >= 0 ? sort : "date";
        state.order = params.get("order") === "asc" ? "asc" : "desc";
        state.limit = Number.isInteger(limit) && limit >= 1 && limit <= 100
            ? limit : DEFAULT_LIMIT;
        state.offset = Number.isInteger(offset) && offset >= 0
            ? Math.floor(offset / state.limit) * state.limit : 0;
    }

    function writeUrl(method) {
        var params = new URLSearchParams();
        if (state.group) params.set("group", state.group);
        if (state.type) params.set("type", state.type);
        if (state.q) params.set("q", state.q);
        if (state.range !== "all") params.set("range", state.range);
        if (state.sort !== "date") params.set("sort", state.sort);
        if (state.order !== "desc") params.set("order", state.order);
        if (state.limit !== DEFAULT_LIMIT) params.set("limit", String(state.limit));
        if (state.offset > 0) params.set("offset", String(state.offset));

        var query = params.toString();
        var url = window.location.pathname + (query ? "?" + query : "");
        if (method === "replace") {
            window.history.replaceState({}, "", url);
        } else {
            window.history.pushState({}, "", url);
        }
    }

    function renderChips() {
        var chips = document.getElementById("chips");
        chips.replaceChildren();
        var active = [];
        if (state.group) active.push(["group", "verdict: " + LABELS[state.group]]);
        if (state.type) active.push(["type", "type: " + state.type]);
        if (state.range !== "all") active.push(["range", "range: " + state.range]);
        if (state.q) active.push(["q", "search: " + state.q]);

        active.forEach(function (item) {
            var chip = document.createElement("span");
            chip.className = "history-chip";
            var label = document.createElement("span");
            label.textContent = item[1];
            var remove = document.createElement("button");
            remove.type = "button";
            remove.dataset.remove = item[0];
            remove.setAttribute("aria-label", "Remove " + item[1]);
            remove.textContent = "×";
            chip.append(label, remove);
            chips.appendChild(chip);
        });
    }

    function applyActiveState() {
        root.querySelectorAll(".history-stat").forEach(function (card) {
            var active = card.dataset.group === state.group;
            card.classList.toggle("is-active", active);
            card.setAttribute("aria-pressed", String(active));
        });
        root.querySelectorAll("#ty [data-type]").forEach(function (button) {
            button.setAttribute("aria-pressed", String(button.dataset.type === state.type));
        });

        var range = document.getElementById("dt");
        if (range) range.value = state.range;
        var search = document.getElementById("q");
        if (search && search.value !== state.q) search.value = state.q;

        root.querySelectorAll(".history-table th").forEach(function (header) {
            var sort = header.dataset.sort;
            header.setAttribute(
                "aria-sort",
                !sort || sort !== state.sort
                    ? "none"
                    : state.order === "asc" ? "ascending" : "descending"
            );
        });
        renderChips();
    }

    function renderSummary(summary) {
        text("historyCountTotal", numberValue(summary.total));
        text("historyCountMalicious", numberValue(summary.malicious));
        text("historyCountSuspicious", numberValue(summary.suspicious));
        text("historyCountClean", numberValue(summary.clean));
        text("historyCountFailed", numberValue(summary.failed));
        text("historyCountUnknown", numberValue(summary.unknown));
        text("historyCountInProgress", numberValue(summary.in_progress));

        var distribution = document.getElementById("dist");
        distribution.replaceChildren();
        GROUPS.forEach(function (group) {
            var count = numberValue(summary[group]);
            if (!count) return;
            var segment = document.createElement("i");
            segment.className = "history-distribution-segment " + groupClass(group);
            segment.style.flex = String(count);
            segment.title = LABELS[group] + ": " + String(count);
            segment.setAttribute("aria-label", segment.title);
            distribution.appendChild(segment);
        });
        applyActiveState();
    }

    function targetFor(item) {
        return item.ioc || item.filename || item.id || "";
    }

    function compactTime(value) {
        var timestamp = Date.parse(value || "");
        if (!Number.isFinite(timestamp)) return "-";
        var minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60000));
        if (minutes < 60) return String(minutes) + "m ago";
        var hours = Math.floor(minutes / 60);
        if (hours < 24) return String(hours) + "h ago";
        return String(Math.floor(hours / 24)) + "d ago";
    }

    function appendDetail(dl, label, value, className) {
        var dt = document.createElement("dt");
        dt.textContent = label;
        var dd = document.createElement("dd");
        if (className) dd.className = className;
        dd.textContent = value === null || value === undefined || value === ""
            ? "-" : String(value);
        dl.append(dt, dd);
    }

    function renderDrawer(item) {
        drawerBody.replaceChildren();

        var group = item.verdict_group || "unknown";
        var groupClassName = groupClass(group);
        var heading = document.createElement("h3");
        heading.textContent = targetFor(item);

        var verdict = document.createElement("span");
        verdict.className = "history-verdict history-drawer-verdict " + groupClassName;
        verdict.textContent = item.verdict || LABELS[group] || "UNKNOWN";

        var score = null;
        if (item.score !== null && item.score !== undefined) {
            score = Math.max(0, Math.min(100, numberValue(item.score)));
        }
        var scoreBlock = null;
        if (score !== null) {
            scoreBlock = document.createElement("div");
            scoreBlock.className = "history-drawer-score " + groupClassName;
            var scoreLabel = document.createElement("div");
            scoreLabel.className = "history-drawer-score-label";
            scoreLabel.textContent = "Risk score";
            var scoreValue = document.createElement("div");
            scoreValue.className = "history-drawer-score-value";
            scoreValue.textContent = String(score);
            var scoreSuffix = document.createElement("small");
            scoreSuffix.textContent = "/100";
            scoreValue.appendChild(scoreSuffix);
            scoreBlock.append(scoreLabel, scoreValue);
        }

        var details = document.createElement("dl");
        appendDetail(details, "ID", item.id);
        appendDetail(details, "Type", item.analysis_type);
        appendDetail(details, "Target", targetFor(item));
        appendDetail(details, "Status", item.status, "history-drawer-status " + groupClassName);
        appendDetail(details, "Created", item.created_at);
        appendDetail(details, "Completed", item.completed_at);

        var report = document.createElement("a");
        report.className = "history-button history-drawer-report";
        report.href = "/report/" + encodeURIComponent(String(item.id || ""));
        report.textContent = "Open full report";

        drawerBody.append(heading, verdict);
        if (scoreBlock) drawerBody.appendChild(scoreBlock);
        drawerBody.append(details);

        if (item.status === "failed") {
            var error = document.createElement("p");
            error.className = "history-drawer-error";
            error.textContent = item.current_step || "Analysis failed.";
            drawerBody.appendChild(error);
        }
        drawerBody.appendChild(report);
    }

    function openDrawer(item, row) {
        if (!item) return;
        activeRow = row;
        renderDrawer(item);
        drawer.hidden = false;
        drawerBackdrop.hidden = false;
        drawer.classList.add("is-open");
        previousBodyOverflow = document.body.style.overflow;
        document.body.style.overflow = "hidden";
        drawerClose.focus();
    }

    function closeDrawer(restoreFocus) {
        if (drawer.hidden) return;
        drawer.classList.remove("is-open");
        drawer.hidden = true;
        drawerBackdrop.hidden = true;
        document.body.style.overflow = previousBodyOverflow;
        previousBodyOverflow = "";
        if (restoreFocus !== false && activeRow && document.body.contains(activeRow)) {
            activeRow.focus();
        }
        activeRow = null;
    }

    function drawerFocusables() {
        return Array.prototype.slice.call(drawer.querySelectorAll(
            "button, a[href], input, select, textarea, [tabindex]:not([tabindex='-1'])"
        ));
    }

    function handleDrawerKeydown(event) {
        if (drawer.hidden) return;
        if (event.key === "Escape") {
            event.preventDefault();
            closeDrawer();
            return;
        }
        if (event.key !== "Tab") return;
        var focusables = drawerFocusables();
        if (!focusables.length) return;
        var first = focusables[0];
        var last = focusables[focusables.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    }

    function renderRows(items) {
        var body = document.getElementById("tb");
        closeDrawer(false);
        rowsById = Object.create(null);
        body.replaceChildren();

        items.forEach(function (item) {
            var group = item.verdict_group || "unknown";
            var id = String(item.id || "");
            rowsById[id] = item;
            var row = document.createElement("tr");
            row.className = "history-row " + groupClass(group);
            row.dataset.id = id;
            row.tabIndex = 0;

            var typeCell = document.createElement("td");
            var typeLabel = document.createElement("span");
            typeLabel.className = "history-type";
            typeLabel.textContent = item.analysis_type || "-";
            typeCell.appendChild(typeLabel);

            var targetCell = document.createElement("td");
            var targetBox = document.createElement("div");
            targetBox.className = "history-target";
            var targetLink = document.createElement("a");
            targetLink.href = "/report/" + encodeURIComponent(id);
            targetLink.textContent = String(targetFor(item));
            targetLink.title = targetLink.textContent;
            targetBox.appendChild(targetLink);
            var idLabel = document.createElement("div");
            idLabel.className = "history-id";
            idLabel.textContent = "#" + id;
            targetCell.append(targetBox, idLabel);

            var verdictCell = document.createElement("td");
            var verdict = document.createElement("span");
            verdict.className = "history-verdict " + groupClass(group);
            verdict.textContent = item.verdict || LABELS[group] || "UNKNOWN";
            verdictCell.appendChild(verdict);

            var scoreCell = document.createElement("td");
            if (item.score === null || item.score === undefined) {
                scoreCell.textContent = "-";
            } else {
                var score = Math.max(0, Math.min(100, numberValue(item.score)));
                var risk = document.createElement("div");
                risk.className = "history-risk " + groupClass(group);
                var scoreLabel = document.createElement("b");
                scoreLabel.className = "history-score";
                scoreLabel.textContent = String(score);
                var track = document.createElement("i");
                track.className = "history-risk-track";
                var fill = document.createElement("u");
                fill.className = "history-risk-fill " + groupClass(group);
                fill.style.width = String(score) + "%";
                track.appendChild(fill);
                risk.append(scoreLabel, track);
                scoreCell.appendChild(risk);
            }

            var statusCell = document.createElement("td");
            var status = document.createElement("span");
            status.className = "history-status";
            if (group === "failed" || group === "in_progress") {
                status.classList.add(groupClass(group));
            }
            status.textContent = item.status || "-";
            statusCell.appendChild(status);

            var timeCell = document.createElement("td");
            timeCell.title = item.created_at || "";
            timeCell.textContent = compactTime(item.created_at);

            row.append(typeCell, targetCell, verdictCell, scoreCell, statusCell, timeCell);
            body.appendChild(row);
        });
    }

    function updatePager(total) {
        var count = numberValue(total);
        text("cnt", count ? "Showing " + (state.offset + 1) + "-" +
            Math.min(state.offset + state.limit, count) + " / " + count + " analyses" :
            "Showing 0 / 0 analyses");
        document.getElementById("historyPrev").disabled = state.offset <= 0;
        document.getElementById("historyNext").disabled = state.offset + state.limit >= count;
    }

    function showListError() {
        var error = document.getElementById("historyError");
        error.textContent = "Unable to load analysis history.";
        error.hidden = false;
        document.getElementById("historyLoading").hidden = true;
        document.getElementById("em").hidden = true;
    }

    function showSummaryError() {
        var error = document.getElementById("historySummaryError");
        error.textContent = "Summary unavailable.";
        error.hidden = false;
    }

    async function loadSummary() {
        try {
            var response = await fetch("/api/analysis/history/summary", {
                signal: summaryController.signal
            });
            if (!response.ok) throw new Error("summary " + response.status);
            renderSummary(await response.json());
        } catch (error) {
            if (error.name !== "AbortError") showSummaryError();
        }
    }

    async function loadList(allowClamp) {
        var clampAllowed = allowClamp !== false;
        var currentRequest = ++requestNumber;
        if (listController) listController.abort();
        listController = new AbortController();
        closeDrawer(false);
        rowsById = Object.create(null);
        setExportBusy(true);

        var params = new URLSearchParams({
            limit: String(state.limit),
            offset: String(state.offset),
            sort: state.sort,
            order: state.order
        });
        if (state.group) params.set("group", state.group);
        if (state.type) params.set("type", state.type);
        if (state.q) params.set("q", state.q);
        if (state.range !== "all") params.set("range", state.range);

        document.getElementById("historyLoading").hidden = false;
        document.getElementById("historyError").hidden = true;
        document.getElementById("em").hidden = true;

        try {
            var response = await fetch("/api/analysis/history/?" + params.toString(), {
                signal: listController.signal
            });
            if (currentRequest !== requestNumber) return;
            if (!response.ok) throw new Error("history " + response.status);
            var payload = await response.json();
            if (currentRequest !== requestNumber) return;

            var items = Array.isArray(payload.items) ? payload.items : [];
            var total = numberValue(payload.total);
            lastHistoryTotal = total;
            if (!items.length && total > 0 && state.offset >= total && clampAllowed) {
                state.offset = Math.max(0, Math.floor((total - 1) / state.limit) * state.limit);
                writeUrl("replace");
                applyActiveState();
                loadList(false);
                return;
            }

            renderRows(items);
            document.getElementById("historyLoading").hidden = true;
            document.getElementById("em").hidden = items.length !== 0;
            updatePager(total);
            setExportBusy(false);
        } catch (error) {
            if (error.name === "AbortError" || currentRequest !== requestNumber) return;
            lastHistoryTotal = 0;
            setExportBusy(false);
            showListError();
        }
    }

    function changeState(method, update) {
        clearSearchTimer();
        update();
        state.offset = 0;
        writeUrl(method);
        applyActiveState();
        loadList();
    }

    function changePage(delta) {
        clearSearchTimer();
        state.offset = Math.max(0, state.offset + delta * state.limit);
        writeUrl("push");
        applyActiveState();
        loadList();
        root.querySelector(".history-table-shell").scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }

    root.addEventListener("click", function (event) {
        var card = event.target.closest(".history-stat");
        var type = event.target.closest("#ty [data-type]");
        var remove = event.target.closest("[data-remove]");
        var sort = event.target.closest(".history-sort");
        var row = event.target.closest(".history-row");

        if (card) {
            changeState("push", function () {
                state.group = state.group === card.dataset.group ? "" : card.dataset.group;
            });
        } else if (type) {
            changeState("push", function () { state.type = type.dataset.type; });
        } else if (remove) {
            changeState("push", function () {
                if (remove.dataset.remove === "group") state.group = "";
                if (remove.dataset.remove === "type") state.type = "";
                if (remove.dataset.remove === "range") state.range = "all";
                if (remove.dataset.remove === "q") state.q = "";
            });
        } else if (sort) {
            changeState("push", function () {
                state.order = state.sort === sort.dataset.sort && state.order === "desc" ? "asc" : "desc";
                state.sort = sort.dataset.sort;
            });
        } else if (event.target.id === "historyPrev" && state.offset >= state.limit) {
            changePage(-1);
        } else if (event.target.id === "historyNext" && state.offset + state.limit < Number.MAX_SAFE_INTEGER) {
            changePage(1);
        } else if (event.target.closest("#historyExport")) {
            if (lastHistoryTotal > HISTORY_EXPORT_CAP) {
                showExportLimitError();
            } else if (!exportButton.disabled) {
                window.location.assign(exportUrl());
            }
        } else if (event.target === drawerBackdrop) {
            closeDrawer();
        } else if (event.target.closest("#historyDrawerClose")) {
            closeDrawer();
        } else if (row && !event.target.closest("a")) {
            openDrawer(rowsById[row.dataset.id], row);
        }
    });

    root.addEventListener("keydown", function (event) {
        handleDrawerKeydown(event);
        var target = event.target;
        var editing = target.matches && target.matches("input, textarea, select") || target.isContentEditable;
        if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !editing) {
            event.preventDefault();
            document.getElementById("q").focus();
        } else if ((event.key === "Enter" || event.key === " ") && target.matches && target.matches(".history-sort")) {
            event.preventDefault();
            target.click();
        } else if (event.key === "Enter" && target.matches && target.matches(".history-row")) {
            event.preventDefault();
            openDrawer(rowsById[target.dataset.id], target);
        }
    });

    drawerClose.addEventListener("click", closeDrawer);

    document.getElementById("dt").addEventListener("change", function (event) {
        changeState("push", function () { state.range = event.target.value; });
    });

    document.getElementById("q").addEventListener("input", function (event) {
        clearSearchTimer();
        state.q = event.target.value;
        state.offset = 0;
        writeUrl("replace");
        searchTimer = window.setTimeout(function () {
            searchTimer = null;
            applyActiveState();
            loadList();
        }, 250);
    });

    window.addEventListener("popstate", function () {
        clearSearchTimer();
        readUrl();
        applyActiveState();
        loadList();
    });

    readUrl();
    applyActiveState();
    loadSummary();
    loadList();
}());
