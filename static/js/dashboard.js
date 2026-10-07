document.addEventListener('DOMContentLoaded', function () {
    const dashboard = document.querySelector('.dash-page');
    if (!dashboard) return;

    const byId = (id) => dashboard.querySelector(`#${id}`);
    const svgNamespace = 'http://www.w3.org/2000/svg';
    const COUNTRY_CENTROIDS = {
        US: [-98, 39, 'United States'], CA: [-106, 56, 'Canada'], MX: [-102, 23, 'Mexico'],
        BR: [-52, -10, 'Brazil'], AR: [-64, -34, 'Argentina'], CL: [-71, -33, 'Chile'],
        CO: [-74, 4, 'Colombia'], PE: [-75, -9, 'Peru'], VE: [-66, 8, 'Venezuela'],
        GB: [-3, 55, 'United Kingdom'], IE: [-8, 53, 'Ireland'], FR: [2, 46, 'France'],
        DE: [10, 51, 'Germany'], NL: [5.3, 52.1, 'Netherlands'], BE: [4.7, 50.5, 'Belgium'],
        LU: [6.1, 49.8, 'Luxembourg'], ES: [-4, 40, 'Spain'], PT: [-8, 39.5, 'Portugal'],
        IT: [12.5, 42.5, 'Italy'], CH: [8.2, 46.8, 'Switzerland'], AT: [14.5, 47.5, 'Austria'],
        PL: [19, 52, 'Poland'], CZ: [15.5, 49.8, 'Czechia'], SK: [19.5, 48.7, 'Slovakia'],
        HU: [19.5, 47, 'Hungary'], RO: [25, 46, 'Romania'], BG: [25, 42.7, 'Bulgaria'],
        GR: [22, 39, 'Greece'], UA: [31, 49, 'Ukraine'], RU: [100, 60, 'Russia'],
        TR: [35, 39, 'Türkiye'], NO: [9, 62, 'Norway'], SE: [15, 62, 'Sweden'],
        FI: [26, 64, 'Finland'], DK: [9.5, 56, 'Denmark'], IS: [-19, 65, 'Iceland'],
        EE: [25.5, 58.7, 'Estonia'], LV: [24.6, 56.9, 'Latvia'], LT: [24, 55.2, 'Lithuania'],
        CN: [104, 35, 'China'], JP: [138, 37, 'Japan'], KR: [127.8, 36, 'South Korea'],
        HK: [114.17, 22.3, 'Hong Kong'], TW: [121, 24, 'Taiwan'], IN: [79, 22, 'India'],
        PK: [69, 30, 'Pakistan'], BD: [90, 24, 'Bangladesh'], LK: [80.7, 7.9, 'Sri Lanka'],
        NP: [84, 28, 'Nepal'], TH: [101, 15, 'Thailand'], VN: [108, 16, 'Vietnam'],
        KH: [105, 13, 'Cambodia'], MY: [102, 4, 'Malaysia'], SG: [103.8, 1.3, 'Singapore'],
        ID: [117, -2, 'Indonesia'], PH: [122, 12, 'Philippines'], AU: [134, -25, 'Australia'],
        NZ: [172, -41, 'New Zealand'], MU: [57.55, -20.2, 'Mauritius'], ZA: [24, -29, 'South Africa'],
        NG: [8, 9, 'Nigeria'], KE: [38, 0, 'Kenya'], EG: [30, 27, 'Egypt'], MA: [-7, 32, 'Morocco'],
        GH: [-2, 8, 'Ghana'], AE: [54, 24, 'United Arab Emirates'], SA: [45, 24, 'Saudi Arabia'],
        IL: [35, 31, 'Israel'], IR: [53, 32, 'Iran'], IQ: [44, 33, 'Iraq'], QA: [51, 25, 'Qatar'],
        KW: [47.5, 29.3, 'Kuwait'], BH: [50.5, 26, 'Bahrain'], JO: [36, 31, 'Jordan'],
        LB: [35.8, 33.8, 'Lebanon'], TN: [9, 34, 'Tunisia'], DZ: [3, 28, 'Algeria'],
        ET: [40, 9, 'Ethiopia'], TZ: [35, -6, 'Tanzania'], UG: [32, 1, 'Uganda'],
        CI: [-5.5, 7.5, 'Côte d’Ivoire'], SN: [-14.5, 14.5, 'Senegal'],
        UY: [-56, -33, 'Uruguay'], BO: [-64, -17, 'Bolivia'], EC: [-78, -1, 'Ecuador'],
        PA: [-80, 9, 'Panama'], CR: [-84, 10, 'Costa Rica'], DO: [-70.2, 19, 'Dominican Republic'],
        CU: [-79.5, 21.5, 'Cuba'], JM: [-77.3, 18.1, 'Jamaica'], PR: [-66.5, 18.2, 'Puerto Rico'],
        CY: [33, 35, 'Cyprus'], MT: [14.4, 35.9, 'Malta'], RS: [21, 44, 'Serbia'],
        HR: [16, 45, 'Croatia'], SI: [14.9, 46.1, 'Slovenia'], BA: [17.8, 44, 'Bosnia and Herzegovina'],
    };
    const COUNTRY_NUMERIC_IDS = {
        US: '840', CA: '124', MX: '484', BR: '076', AR: '032', CL: '152', CO: '170', PE: '604', VE: '862',
        GB: '826', IE: '372', FR: '250', DE: '276', NL: '528', BE: '056', LU: '442', ES: '724', PT: '620',
        IT: '380', CH: '756', AT: '040', PL: '616', CZ: '203', SK: '703', HU: '348', RO: '642', BG: '100',
        GR: '300', UA: '804', RU: '643', TR: '792', NO: '578', SE: '752', FI: '246', DK: '208', IS: '352',
        EE: '233', LV: '428', LT: '440', CN: '156', JP: '392', KR: '410', HK: '344', TW: '158', IN: '356',
        PK: '586', BD: '050', LK: '144', NP: '524', TH: '764', VN: '704', KH: '116', MY: '458', SG: '702',
        ID: '360', PH: '608', AU: '036', NZ: '554', MU: '480', ZA: '710', NG: '566', KE: '404', EG: '818',
        MA: '504', GH: '288', AE: '784', SA: '682', IL: '376', IR: '364', IQ: '368', QA: '634', KW: '414',
        BH: '048', JO: '400', LB: '422', TN: '788', DZ: '012', ET: '231', TZ: '834', UG: '800', CI: '384',
        SN: '686', UY: '858', BO: '068', EC: '218', PA: '591', CR: '188', DO: '214', CU: '192', JM: '388',
        PR: '630', CY: '196', MT: '470', RS: '688', HR: '191', SI: '705', BA: '070',
    };

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
            {key: 'phishing_count', label: 'Phishing', group: 'phishing'},
            {key: 'suspicious_count', label: 'Suspicious', group: 'suspicious'},
            {key: 'spam_count', label: 'Spam', group: 'spam'},
            {key: 'clean_count', label: 'Clean', group: 'clean'},
            {key: 'unknown_count', label: 'Unknown', group: 'unknown'},
        ].map((item) => ({...item, count: safeCount(data[item.key])}));
        const total = safeCount(data.total_analyses);
        bar.replaceChildren();
        legend.replaceChildren();
        bar.setAttribute('aria-label', `Verdict distribution: ${groups.map((item) => `${item.label} ${item.count}`).join(', ')}`);

        groups.forEach((item) => {
            const segment = document.createElement('span');
            segment.className = `dash-verdict-segment dash-segment--${item.group}`;
            segment.style.flexBasis = '0px';
            segment.style.flexGrow = String(total > 0 ? item.count : 0);
            segment.setAttribute('aria-hidden', 'true');
            bar.appendChild(segment);
        });

        groups.forEach((item) => {
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

    function verdictStyle(verdict) {
        const normalized = String(verdict || '').toUpperCase();
        if (normalized === 'MALICIOUS') return 'danger';
        if (normalized === 'PHISHING') return 'phishing';
        if (normalized === 'SUSPICIOUS') return 'warning';
        if (normalized === 'SPAM') return 'spam';
        if (normalized === 'CLEAN') return 'success';
        return 'neutral';
    }

    function countryVerdictClass(verdict) {
        const normalized = String(verdict || '').toUpperCase();
        if (normalized === 'MALICIOUS') return 'malicious';
        if (normalized === 'PHISHING') return 'phishing';
        if (normalized === 'SUSPICIOUS') return 'suspicious';
        if (normalized === 'SPAM') return 'spam';
        if (normalized === 'CLEAN') return 'clean';
        return 'other';
    }

    function countryName(code) {
        return COUNTRY_CENTROIDS[code]?.[2] || code;
    }

    function updateCountryLocations(countryRows, coveredValue, totalValue) {
        const map = byId('dash-country-map');
        const markers = byId('dash-country-markers');
        const list = byId('dash-country-list');
        const empty = byId('dash-country-empty');
        const notMapped = byId('dash-country-not-mapped');
        const coverage = byId('dash-country-coverage');
        if (!map || !markers || !list || !empty || !notMapped || !coverage) return;

        const rows = Array.isArray(countryRows)
            ? countryRows.filter((item) => (
                item && typeof item.code === 'string' && /^[A-Za-z]{2}$/.test(item.code)
            ))
            : [];
        const normalizedRows = rows.map((item) => ({
            code: item.code.toUpperCase(),
            ips: safeCount(item.ips),
            analyses: safeCount(item.analyses),
            worst_verdict: String(item.worst_verdict || 'UNKNOWN').toUpperCase(),
        }));
        markers.replaceChildren();
        list.replaceChildren();
        const countryClasses = [
            'malicious', 'phishing', 'suspicious', 'spam', 'clean', 'other',
        ].map((verdict) => `dash-map-country--${verdict}`);
        map.querySelectorAll('.dash-map-country').forEach((path) => {
            path.classList.remove(...countryClasses);
            path.removeAttribute('tabindex');
            path.removeAttribute('aria-label');
            path.replaceChildren();
        });

        const unmappedCodes = normalizedRows
            .filter((item) => !COUNTRY_CENTROIDS[item.code])
            .map((item) => item.code);
        notMapped.textContent = `Not on map: ${unmappedCodes.length}${unmappedCodes.length ? ` (${unmappedCodes.join(', ')})` : ''}`;

        let plottedCount = 0;
        const labelledPositions = [];
        normalizedRows.forEach((item) => {
            const numericId = COUNTRY_NUMERIC_IDS[item.code];
            const countryPath = numericId
                ? map.querySelector(`.dash-map-country[data-n3="${numericId}"]`)
                : null;
            if (countryPath) {
                const countryClass = countryVerdictClass(item.worst_verdict);
                const titleText = `${countryName(item.code)}: ${item.ips} unique IPs, ${item.analyses} analyses, ${item.worst_verdict}`;
                countryPath.classList.add(`dash-map-country--${countryClass}`);
                countryPath.setAttribute('tabindex', '0');
                countryPath.setAttribute('aria-label', titleText);
                countryPath.appendChild(svgElement('title', {}, titleText));
            }

            const centroid = COUNTRY_CENTROIDS[item.code];
            if (!centroid) return;
            const [longitude, latitude] = centroid;
            const x = (longitude + 170) * 3;
            const y = (80 - latitude) * 3;
            const radius = Math.max(8, Math.min(26, Math.sqrt(item.ips)));
            const style = verdictStyle(item.worst_verdict);
            const group = svgElement('g', {});
            const halo = svgElement('circle', {
                cx: x, cy: y, r: radius + 5,
                class: `dash-map-marker-halo--${style}`,
            });
            const marker = svgElement('circle', {
                cx: x, cy: y, r: radius,
                class: `dash-map-marker dash-map-marker--${style}`,
            });
            const title = svgElement(
                'title', {},
                `${countryName(item.code)}: ${item.ips} unique IPs, ${item.analyses} analyses, ${item.worst_verdict}`,
            );
            marker.appendChild(title);
            group.appendChild(halo);
            group.appendChild(marker);
            const labelIsCrowded = labelledPositions.some((position) => (
                Math.hypot(position.x - x, position.y - y) < 14
            ));
            if (!labelIsCrowded) {
                const labelToLeft = x > 930;
                const labelX = labelToLeft ? x - radius - 5 : x + radius + 5;
                const labelY = y + 4;
                const label = svgElement('text', {
                    x: labelX,
                    y: labelY,
                    'text-anchor': labelToLeft ? 'end' : 'start',
                    class: 'dash-map-label',
                }, `${item.code} ${item.ips}`);
                group.appendChild(label);
                labelledPositions.push({x, y});
            }
            markers.appendChild(group);
            plottedCount += 1;
        });
        map.setAttribute('aria-label', `Indicator locations map with ${plottedCount} country markers`);

        normalizedRows.slice(0, 8).forEach((item) => {
            const listItem = document.createElement('li');
            listItem.className = 'dash-country-item';
            appendText(listItem, 'span', 'dash-country-name', `${countryName(item.code)} (${item.code})`);
            appendText(listItem, 'span', 'dash-country-count', `${item.ips} unique IP${item.ips === 1 ? '' : 's'}`);
            appendText(
                listItem,
                'span',
                `dash-country-verdict dash-country-verdict--${verdictStyle(item.worst_verdict)}`,
                item.worst_verdict,
            );
            list.appendChild(listItem);
        });

        empty.textContent = normalizedRows.length ? '' : 'No IP country data available yet.';
        coverage.textContent = `${safeCount(coveredValue)} of ${safeCount(totalValue)} analyses have a country (IP indicators only)`;
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
            updateCountryLocations(data.country_stats, data.country_covered, data.total_analyses);
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
