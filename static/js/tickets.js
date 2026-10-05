(() => {
    "use strict";

    const initializeTicketsPage = () => {
        const page = document.querySelector(".tickets-page");
        if (!page) return;

        const rows = Array.from(page.querySelectorAll(".tickets-row"));
        const searchInput = page.querySelector("#ticketSearch");
        const filterButtons = Array.from(page.querySelectorAll(".tickets-filter"));
        const filteredEmpty = page.querySelector("#ticketFilteredEmpty");
        const distribution = page.querySelector("#ticketDistribution");
        const verdicts = ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"];
        const verdictClass = {
            MALICIOUS: "tickets-segment-malicious",
            SUSPICIOUS: "tickets-segment-suspicious",
            CLEAN: "tickets-segment-clean",
            UNKNOWN: "tickets-segment-unknown",
        };
        const countTargets = {
            ALL: "ticketFilterCountAll",
            MALICIOUS: "ticketFilterCountMalicious",
            SUSPICIOUS: "ticketFilterCountSuspicious",
            CLEAN: "ticketFilterCountClean",
            UNKNOWN: "ticketFilterCountUnknown",
        };

        const counts = { MALICIOUS: 0, SUSPICIOUS: 0, CLEAN: 0, UNKNOWN: 0 };
        rows.forEach((row) => {
            const verdict = (row.dataset.verdict || "UNKNOWN").toUpperCase();
            counts[verdicts.includes(verdict) ? verdict : "UNKNOWN"] += 1;
        });

        const writeCount = (id, value) => {
            const target = page.querySelector(`#${id}`);
            if (target) target.textContent = String(value);
        };

        writeCount("ticketCountTotal", rows.length);
        writeCount("ticketCountMalicious", counts.MALICIOUS);
        writeCount("ticketCountSuspicious", counts.SUSPICIOUS);
        writeCount("ticketCountClean", counts.CLEAN);
        writeCount("ticketCountUnknown", counts.UNKNOWN);
        writeCount(countTargets.ALL, rows.length);
        verdicts.forEach((verdict) => writeCount(countTargets[verdict], counts[verdict]));

        if (distribution) {
            distribution.replaceChildren();
            verdicts.forEach((verdict) => {
                const count = counts[verdict];
                if (!count || !rows.length) return;
                const segment = document.createElement("span");
                segment.classList.add("tickets-distribution-segment", verdictClass[verdict]);
                segment.style.flexBasis = `${(count / rows.length) * 100}%`;
                segment.setAttribute("aria-label", `${verdict.toLowerCase()}: ${count}`);
                distribution.appendChild(segment);
            });
            distribution.setAttribute(
                "aria-label",
                `Ticket verdict proportions: ${verdicts.map((verdict) => `${verdict.toLowerCase()} ${counts[verdict]}`).join(", ")}`,
            );
        }

        let activeVerdict = "ALL";
        const applyFilters = () => {
            const query = (searchInput?.value || "").trim().toLocaleLowerCase();
            let visibleCount = 0;
            rows.forEach((row) => {
                const verdict = (row.dataset.verdict || "UNKNOWN").toUpperCase();
                const searchText = (row.dataset.search || "").toLocaleLowerCase();
                const matchesVerdict = activeVerdict === "ALL" || verdict === activeVerdict;
                const matchesSearch = !query || searchText.includes(query);
                const visible = matchesVerdict && matchesSearch;
                row.hidden = !visible;
                if (visible) visibleCount += 1;
            });
            if (filteredEmpty) filteredEmpty.hidden = visibleCount !== 0;
        };

        filterButtons.forEach((button) => {
            button.addEventListener("click", () => {
                activeVerdict = button.dataset.filter || "ALL";
                filterButtons.forEach((candidate) => {
                    const active = candidate === button;
                    candidate.classList.toggle("tickets-filter-active", active);
                    candidate.setAttribute("aria-pressed", String(active));
                });
                applyFilters();
            });
        });
        searchInput?.addEventListener("input", applyFilters);
        applyFilters();
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initializeTicketsPage, { once: true });
    } else {
        initializeTicketsPage();
    }
})();
