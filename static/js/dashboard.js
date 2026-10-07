document.addEventListener('DOMContentLoaded', function () {
    const dashboard = document.querySelector('.dash-page');
    if (!dashboard) return;

    const byId = (id) => dashboard.querySelector(`#${id}`);
    const svgNamespace = 'http://www.w3.org/2000/svg';

    function safeCount(value) {
        const count = Number(value);
        return Number.isFinite(count) && count > 0 ? count : 0;
    }

    function parseUtc(value) {
        if (typeof value !== 'string' || !value.trim()) return null;
        const raw = value.trim();
        const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?$/i);
        if (!match) return null;
        const [, yearText, monthText, dayText, hourText, minuteText, secondText = '0', zone = ''] = match;
        const year = Number(yearText);
        const month = Number(monthText);
        const day = Number(dayText);
        const hour = Number(hourText);
        const minute = Number(minuteText);
        const second = Number(secondText);
        const calendarCheck = new Date(Date.UTC(year, month - 1, day));
        if (
            calendarCheck.getUTCFullYear() !== year ||
            calendarCheck.getUTCMonth() !== month - 1 ||
            calendarCheck.getUTCDate() !== day ||
            hour > 23 || minute > 59 || second > 59
        ) return null;
        const normalized = `${raw.replace(' ', 'T')}${zone ? '' : 'Z'}`;
        const parsed = new Date(normalized);
        return Number.isFinite(parsed.getTime()) ? parsed : null;
    }

    function formatUtc(value) {
        const date = parseUtc(value);
        if (!date) return '—';
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const pad = (part) => String(part).padStart(2, '0');
        return `${pad(date.getUTCDate())} ${months[date.getUTCMonth()]} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
    }

    function appendText(parent, tagName, className, value) {
        const element = document.createElement(tagName);
        if (className) element.className = className;
        element.textContent = value;
        parent.appendChild(element);
        return element;
    }

    function updateTotals(data) {
        const fields = [
            ['stat-total-analyses', data.total_analyses],
            ['stat-malicious', data.malicious_count],
            ['stat-suspicious', data.suspicious_count],
            ['stat-clean', data.clean_count],
        ];
        fields.forEach(([id, value]) => {
            const element = byId(id);
            if (element) element.textContent = String(safeCount(value));
        });
    }

    function updateVerdictDistribution(data) {
        const bar = byId('verdict-dist-chart');
        const legend = byId('dash-verdict-legend');
        if (!bar || !legend) return;

        const groups = [
            {key: 'malicious_count', label: 'Malicious', group: 'malicious'},
            {key: 'suspicious_count', label: 'Suspicious', group: 'suspicious'},
            {key: 'clean_count', label: 'Clean', group: 'clean'},
            {key: 'phishing_count', label: 'Phishing', group: 'other'},
            {key: 'spam_count', label: 'Spam', group: 'other'},
            {key: 'unknown_count', label: 'Unknown', group: 'other'},
        ].map((item) => ({...item, count: safeCount(data[item.key])}));
        const total = safeCount(data.total_analyses);
        const shownGroups = groups.filter((item, index) => index < 3 || item.count > 0);
        bar.replaceChildren();
        legend.replaceChildren();
        bar.setAttribute('aria-label', `Verdict distribution: ${shownGroups.map((item) => `${item.label} ${item.count}`).join(', ')}`);

        groups.forEach((item) => {
            const segment = document.createElement('span');
            segment.className = `dash-verdict-segment dash-segment--${item.group}`;
            const width = total > 0 ? (item.count / total) * 100 : 0;
            segment.style.flexBasis = `${width}%`;
            segment.setAttribute('aria-hidden', 'true');
            bar.appendChild(segment);
        });

        shownGroups.forEach((item) => {
            const row = document.createElement('div');
            row.className = 'dash-legend-row';
            const label = appendText(row, 'span', 'dash-legend-label', '');
            const dot = document.createElement('i');
            dot.className = `dash-legend-dot dash-segment--${item.group}`;
            dot.setAttribute('aria-hidden', 'true');
            label.appendChild(dot);
            appendText(label, 'span', '', item.label);
            appendText(row, 'strong', 'dash-legend-count', String(item.count));
            legend.appendChild(row);
        });
    }

    function svgElement(name, attributes, text) {
        const element = document.createElementNS(svgNamespace, name);
        Object.entries(attributes || {}).forEach(([key, value]) => element.setAttribute(key, String(value)));
        if (text !== undefined) element.textContent = text;
        return element;
    }

    function updateDailyChart(rows) {
        const chart = byId('dash-daily-chart');
        if (!chart) return;
        const daily = Array.isArray(rows) ? rows : [];
        chart.replaceChildren();
        const plot = {left: 34, right: 552, top: 12, bottom: 150};
        const series = [
            {key: 'malicious', label: 'Malicious', className: 'dash-chart-line--malicious'},
            {key: 'suspicious', label: 'Suspicious', className: 'dash-chart-line--suspicious'},
            {key: 'clean', label: 'Clean', className: 'dash-chart-line--clean'},
        ];
        const maxCount = Math.max(1, ...daily.flatMap((item) => series.map((line) => safeCount(item?.[line.key]))));

        [0, maxCount / 2, maxCount].forEach((value) => {
            const y = plot.bottom - (value / maxCount) * (plot.bottom - plot.top);
            chart.appendChild(svgElement('line', {x1: plot.left, y1: y, x2: plot.right, y2: y, class: 'dash-chart-grid'}));
            chart.appendChild(svgElement('text', {x: plot.left - 8, y: y + 4, 'text-anchor': 'end', class: 'dash-chart-label'}, String(Math.round(value))));
        });

        const pointX = (index) => daily.length <= 1
            ? (plot.left + plot.right) / 2
            : plot.left + (index * (plot.right - plot.left)) / (daily.length - 1);
        series.forEach((line) => {
            const points = daily.map((item, index) => {
                const value = safeCount(item?.[line.key]);
                const y = plot.bottom - (value / maxCount) * (plot.bottom - plot.top);
                return `${pointX(index)},${y}`;
            }).join(' ');
            chart.appendChild(svgElement('polyline', {points, class: `dash-chart-line ${line.className}`}));
        });

        [0, Math.floor((daily.length - 1) / 2), daily.length - 1]
            .filter((index, position, indexes) => index >= 0 && indexes.indexOf(index) === position)
            .forEach((index) => {
                const day = daily[index]?.date;
                if (typeof day !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(day)) return;
                const stamp = parseUtc(`${day}T00:00:00Z`);
                if (!stamp) return;
                const label = `${String(stamp.getUTCDate()).padStart(2, '0')} ${['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][stamp.getUTCMonth()]}`;
                chart.appendChild(svgElement('text', {x: pointX(index), y: 174, 'text-anchor': 'middle', class: 'dash-chart-label'}, label));
            });

        const labels = series.map((line) => `${line.label}: ${daily.map((item) => safeCount(item?.[line.key])).join(', ')}`).join('. ');
        chart.setAttribute('aria-label', `Analyses per day for the last 14 UTC days. ${labels}`);
    }

    function updateScoreBuckets(buckets) {
        const container = byId('dash-score-bars');
        if (!container) return;
        container.replaceChildren();
        const rows = Array.isArray(buckets) ? buckets : [];
        const counts = rows.map((item) => safeCount(item?.count));
        const maxCount = Math.max(1, ...counts);
        rows.forEach((item, index) => {
            const bucket = document.createElement('div');
            bucket.className = 'dash-score-bucket';
            appendText(bucket, 'span', 'dash-score-count', String(counts[index]));
            const track = document.createElement('div');
            track.className = 'dash-score-track';
            const bar = document.createElement('span');
            bar.className = 'dash-score-bar';
            bar.style.height = `${(counts[index] / maxCount) * 100}%`;
            track.appendChild(bar);
            bucket.appendChild(track);
            appendText(bucket, 'span', 'dash-score-label', typeof item?.label === 'string' ? item.label : '—');
            container.appendChild(bucket);
        });
    }

    function updateServerTimes() {
        dashboard.querySelectorAll('.dash-time').forEach((element) => {
            element.textContent = formatUtc(element.getAttribute('data-utc-time') || '');
        });
    }

    async function fetchDashboardStats() {
        const status = byId('dash-data-status');
        try {
            const response = await fetch('/api/dashboard/stats');
            if (!response.ok) {
                if (status) status.textContent = 'Dashboard statistics are temporarily unavailable.';
                return;
            }
            const data = await response.json();
            updateTotals(data);
            updateVerdictDistribution(data);
            updateDailyChart(data.daily_counts);
            updateScoreBuckets(data.score_buckets);
            if (status) status.textContent = '';
        } catch (_error) {
            if (status) status.textContent = 'Dashboard statistics are temporarily unavailable.';
        }
    }

    function createFeedCard(item) {
        const card = document.createElement('article');
        card.className = 'dash-feed-card';

        const meta = document.createElement('div');
        meta.className = 'dash-feed-meta';
        const score = item.threat_score ?? item.score;
        const pill = appendText(meta, 'span', 'dash-pill dash-pill--danger', `Malicious ${score === null || score === undefined ? '—' : score}`);
        pill.setAttribute('aria-label', `Malicious, score ${score === null || score === undefined ? 'unavailable' : `${score} out of 100`}`);
        appendText(meta, 'time', 'dash-feed-time', formatUtc(item.created_at));
        card.appendChild(meta);

        const indicator = item.ioc || item.filename || item.id || '—';
        const indicatorNode = appendText(card, 'div', 'dash-feed-indicator', String(indicator));
        indicatorNode.setAttribute('title', String(indicator));

        if (item.id !== null && item.id !== undefined && String(item.id)) {
            const reportLink = appendText(card, 'a', 'dash-link', 'View report');
            reportLink.href = `/api/reports/${encodeURIComponent(String(item.id))}/html`;
        }
        return card;
    }

    async function fetchMaliciousFeed() {
        const feed = byId('dash-malicious-feed');
        if (!feed) return;
        try {
            const response = await fetch('/api/dashboard/recent?limit=50');
            if (!response.ok) {
                feed.replaceChildren();
                appendText(feed, 'p', 'dash-empty', 'Recent analyses are temporarily unavailable.');
                return;
            }
            const data = await response.json();
            const analyses = Array.isArray(data.items) ? data.items : (Array.isArray(data.analyses) ? data.analyses : []);
            const malicious = analyses
                .filter((item) => String(item?.verdict || '').toUpperCase() === 'MALICIOUS')
                .sort((left, right) => {
                    const leftTime = parseUtc(left?.created_at)?.getTime();
                    const rightTime = parseUtc(right?.created_at)?.getTime();
                    if (leftTime === undefined && rightTime === undefined) return 0;
                    if (leftTime === undefined) return 1;
                    if (rightTime === undefined) return -1;
                    return rightTime - leftTime;
                })
                .slice(0, 5);
            feed.replaceChildren();
            if (!malicious.length) {
                appendText(feed, 'p', 'dash-empty', 'No malicious analyses found in the latest 50 analyses.');
                return;
            }
            malicious.forEach((item) => feed.appendChild(createFeedCard(item)));
        } catch (_error) {
            feed.replaceChildren();
            appendText(feed, 'p', 'dash-empty', 'Recent analyses are temporarily unavailable.');
        }
    }

    const quickIocForm = byId('quick-ioc-form');
    if (quickIocForm) {
        quickIocForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const input = quickIocForm.querySelector('input[name="ioc"]');
            const iocValue = input ? input.value.trim() : '';
            if (!iocValue) {
                window.alert('Please enter an IOC (IP, domain, URL, hash, or email).');
                return;
            }
            window.location.href = `/analysis/ioc?q=${encodeURIComponent(iocValue)}`;
        });
    }

    updateServerTimes();
    void fetchDashboardStats();
    void fetchMaliciousFeed();
    // setInterval(fetchDashboardStats, 30000);
});
