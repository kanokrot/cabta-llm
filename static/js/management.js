(() => {
    "use strict";

    const initializeManagementPage = () => {
        const page = document.querySelector(".mgmt-page");
        if (!page) return;

        const table = page.querySelector("#access-request-table");
        const tbody = table && table.querySelector("tbody");
        const pendingTile = page.querySelector("#pending-request-count");
        const pendingTileCard = pendingTile && pendingTile.closest(".mgmt-stat-pending");
        const requestCount = page.querySelector("#request-count");
        const distribution = page.querySelector("#pending-request-distribution");
        const tableShell = table && table.closest(".mgmt-table-shell");

        const ensureEmptyState = () => {
            let empty = page.querySelector("#empty-access-requests");
            if (!empty) {
                empty = document.createElement("div");
                empty.id = "empty-access-requests";
                empty.className = "mgmt-empty";
                const icon = document.createElement("i");
                icon.className = "bi bi-inbox";
                icon.setAttribute("aria-hidden", "true");
                empty.appendChild(icon);
                const message = document.createElement("p");
                message.textContent = "No pending access requests.";
                empty.appendChild(message);
                if (tableShell && tableShell.parentNode) {
                    tableShell.parentNode.appendChild(empty);
                }
            } else {
                empty.classList.add("mgmt-empty");
            }

            if (!empty.querySelector(".mgmt-empty-title")) {
                const title = document.createElement("h3");
                title.className = "mgmt-empty-title";
                title.textContent = "Queue is clear";
                empty.insertBefore(title, empty.firstChild);
            }
            return empty;
        };

        const parseCreatedAt = (value) => {
            const source = (value || "").trim();
            if (!source) return null;
            const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(source);
            const sqliteTimestamp = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;
            const normalized = sqliteTimestamp.test(source) && !hasTimezone
                ? `${source.replace(" ", "T")}Z`
                : source;
            const date = new Date(normalized);
            return Number.isNaN(date.getTime()) ? null : date;
        };

        const formatRelativeTime = (date) => {
            const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
            if (seconds < 60 && seconds > -60) return "just now";
            const future = seconds < 0;
            const elapsed = Math.abs(seconds);
            const units = [
                [31536000, "y"],
                [2592000, "mo"],
                [604800, "w"],
                [86400, "d"],
                [3600, "h"],
                [60, "m"],
            ];
            const [size, suffix] = units.find(([unit]) => elapsed >= unit) || [60, "m"];
            const amount = Math.floor(elapsed / size);
            return future ? `in ${amount}${suffix}` : `${amount}${suffix} ago`;
        };

        page.querySelectorAll(".mgmt-relative-time").forEach((time) => {
            const raw = time.getAttribute("datetime") || time.textContent;
            const parsed = parseCreatedAt(raw);
            if (parsed) time.textContent = formatRelativeTime(parsed);
        });

        const refreshQueueState = () => {
            const count = tbody ? tbody.rows.length : 0;
            if (pendingTile) {
                pendingTile.textContent = String(count);
            }
            if (pendingTileCard) {
                pendingTileCard.classList.toggle("mgmt-stat-pending-active", count > 0);
                pendingTileCard.classList.toggle("mgmt-stat-pending-empty", count === 0);
            }
            if (requestCount) requestCount.textContent = String(count);
            if (distribution) {
                distribution.dataset.hasPending = String(count > 0);
                distribution.setAttribute(
                    "aria-label",
                    count > 0 ? `${count} pending access request(s)` : "No pending access requests",
                );
            }

            const empty = page.querySelector("#empty-access-requests");
            if (count === 0) {
                if (table) table.classList.add("mgmt-table-hidden");
                const state = ensureEmptyState();
                state.hidden = false;
            } else {
                if (table) table.classList.remove("mgmt-table-hidden");
                if (empty) empty.hidden = true;
            }
        };

        refreshQueueState();
        if (tbody && typeof MutationObserver !== "undefined") {
            const observer = new MutationObserver(refreshQueueState);
            observer.observe(tbody, { childList: true });
        }
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initializeManagementPage, { once: true });
    } else {
        initializeManagementPage();
    }
})();
