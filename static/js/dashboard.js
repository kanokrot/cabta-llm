function defangIoc(value, iocType) {
    const raw = typeof value === 'string' ? value : String(value ?? '');
    const type = typeof iocType === 'string' ? iocType.toLowerCase() : 'other';
    if (type === 'hash' || !['url', 'domain', 'ip', 'ip:port'].includes(type)) return raw;
    if (type === 'ip' || type === 'ip:port') return raw.replace(/\./g, '[.]');

    let prefix = '';
    let remainder = raw;
    const scheme = raw.match(/^([a-z][a-z0-9+.-]*:\/\/)(.*)$/i);
    if (scheme) {
        prefix = scheme[1].replace(/^https:/i, 'hxxps:').replace(/^http:/i, 'hxxp:');
        remainder = scheme[2];
    }
    const authority = remainder.match(/^([^/?#]+)(.*)$/);
    if (!authority) return prefix + remainder;
    const at = authority[1].lastIndexOf('@');
    const userInfo = at >= 0 ? authority[1].slice(0, at + 1) : '';
    const hostPort = at >= 0 ? authority[1].slice(at + 1) : authority[1];
    const hostMatch = hostPort.match(/^(\[[^\]]+\]|[^:]+)(.*)$/);
    const host = hostMatch ? hostMatch[1].replace(/\./g, '[.]') : hostPort.replace(/\./g, '[.]');
    return prefix + userInfo + host + (hostMatch ? hostMatch[2] : '') + authority[2];
}

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
        TR: [35, 39, 'T\u00FCrkiye'], NO: [9, 62, 'Norway'], SE: [15, 62, 'Sweden'],
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
        CI: [-5.5, 7.5, 'C\u00F4te d\u2019Ivoire'], SN: [-14.5, 14.5, 'Senegal'],
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
        if (!date) return '\u2014';
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
            appendText(bucket, 'span', 'dash-score-label', typeof item?.label === 'string' ? item.label : '\u2014');
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

    const COUNTRY_CODES_BY_NUMERIC_ID = Object.fromEntries(
        Object.entries(COUNTRY_NUMERIC_IDS).map(([code, numericId]) => [numericId, code]),
    );
    let globe = null;

    function normalizedNumericId(value) {
        return String(value ?? '').padStart(3, '0');
    }

    function countryCenter(code) {
        if (COUNTRY_CENTROIDS[code]) return COUNTRY_CENTROIDS[code];
        const numericId = COUNTRY_NUMERIC_IDS[code];
        const feature = numericId && globe?.featureByNumericId.get(numericId);
        return feature && window.d3 ? window.d3.geoCentroid(feature) : null;
    }

    function mapError(message) {
        const map = byId('dash-country-map');
        const error = byId('dash-map-error');
        if (map) map.hidden = true;
        if (error) {
            error.textContent = message;
            error.hidden = false;
        }
    }

    function initializeGlobe() {
        const map = byId('dash-country-map');
        const focusLabel = byId('dash-country-focus');
        const countriesGroup = byId('dash-map-countries');
        const markersGroup = byId('dash-map-markers');
        if (!map || !countriesGroup || !markersGroup) return;
        if (!window.d3) {
            console.error('Dashboard globe requires the d3 global; globe controls are disabled.');
            mapError('The country globe could not be initialized.');
            return;
        }
        if (!window.topojson) {
            console.error('Dashboard globe requires the topojson global; globe controls are disabled.');
            mapError('The country globe could not be initialized.');
            return;
        }
        const requiredD3Functions = [
            'geoOrthographic', 'geoPath', 'geoGraticule10', 'geoDistance', 'geoContains', 'geoCentroid',
        ];
        const missingD3Function = requiredD3Functions.find((name) => typeof window.d3[name] !== 'function');
        if (missingD3Function) {
            console.error('Dashboard globe requires d3.' + missingD3Function + '; globe controls are disabled.');
            mapError('The country globe could not be initialized.');
            return;
        }
        if (typeof window.topojson.feature !== 'function') {
            console.error('Dashboard globe requires topojson.feature; globe controls are disabled.');
            mapError('The country globe could not be initialized.');
            return;
        }

        const width = 720;
        const height = 500;
        const baseScale = 226;
        const projection = window.d3.geoOrthographic()
            .scale(baseScale).translate([width / 2, height / 2]).clipAngle(90).precision(0.25);
        const card = byId('dash-map-hover-card');
        const hoverGraphics = byId('dash-map-hover-graphics');
        const leader = byId('dash-map-hover-leader');
        const ring = byId('dash-map-hover-ring');
        const crosshair = byId('dash-map-hover-crosshair');
        globe = {
            map, projection, path: window.d3.geoPath(projection), countriesGroup, markersGroup, focusLabel,
            countryFeatures: [], countryNodes: [], countryNodeByNumericId: new Map(),
            featureByNumericId: new Map(), statsByCode: new Map(), markerNodes: [],
            rotation: [0, 20, 0], zoom: 1, topologyLoaded: false, initialViewSet: false,
            drawingFrame: null, animationFrame: null, pointers: new Map(), dragPointerId: null,
            pinchStart: null, suppressClick: false, focusedFeature: null, hoverFeature: null,
            pinnedFeature: null, hasStats: false,
        };
        const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
        const clamp = (value, low, high) => Math.max(low, Math.min(high, value));
        const clampZoom = (value) => clamp(value, 1, 6);

        function makeStars() {
            const group = byId('dash-map-stars');
            if (!group || group.childElementCount) return;
            let state = 0x51a7f13;
            const random = () => {
                state = (state * 1664525 + 1013904223) >>> 0;
                return state / 4294967296;
            };
            for (let i = 0; i < 120; i += 1) {
                const size = i % 13 === 0 ? 'large' : (i % 3 === 0 ? 'medium' : 'small');
                const opacity = i % 4 === 0 ? 'bright' : 'dim';
                const star = svgElement('circle', {
                    cx: (random() * width).toFixed(1), cy: (random() * height).toFixed(1),
                    class: 'dash-map-star dash-map-star--' + size + ' dash-map-star--' + opacity + (i < 12 ? ' is-twinkling' : ''),
                });
                if (i < 12) star.style.animationDelay = (random() * 5).toFixed(2) + 's';
                group.appendChild(star);
            }
        }
        makeStars();

        function requestRender() {
            if (globe && globe.drawingFrame === null) {
                globe.drawingFrame = window.requestAnimationFrame(renderFrame);
            }
        }

        function setFocusedFeature(feature) {
            if (!globe) return;
            if (globe.focusedFeature !== feature) {
                globe.focusedFeature = feature;
                globe.countryNodes.forEach(({feature: candidate, node}) => node.classList.toggle('is-focused', candidate === feature));
            }
            if (!focusLabel) return;
            let text;
            if (!feature) text = 'No country at the globe centre.';
            else {
                const code = COUNTRY_CODES_BY_NUMERIC_ID[normalizedNumericId(feature.id)];
                const name = code ? countryName(code) : (feature.properties?.name || 'Country');
                const stats = code ? globe.statsByCode.get(code) : null;
                text = stats ? name + ' \u2014 ' + stats.ips + ' IP' + (stats.ips === 1 ? '' : 's') +
                    ', ' + stats.analyses + ' analyses, worst: ' + stats.worst_verdict : name;
            }
            if (focusLabel.textContent !== text) focusLabel.textContent = text;
        }

        function fillCard(feature) {
            if (!card || !feature) return;
            const numericId = normalizedNumericId(feature.id);
            const code = COUNTRY_CODES_BY_NUMERIC_ID[numericId] || '';
            const name = (code && countryName(code)) || feature.properties?.name || 'Country';
            const stats = code ? globe.statsByCode.get(code) : null;
            byId('dash-map-hover-name').textContent = name;
            byId('dash-map-hover-code').textContent = code ? 'ISO ' + code : 'ISO \u2014';
            byId('dash-map-hover-indicators').textContent = stats ? String(stats.ips) : '\u2014';
            byId('dash-map-hover-analyses').textContent = stats ? String(stats.analyses) : '\u2014';
            const verdict = byId('dash-map-hover-verdict');
            verdict.textContent = stats ? stats.worst_verdict : '\u2014';
            verdict.className = 'dash-map-hover-verdict' + (stats ? ' dash-country-verdict--' + verdictStyle(stats.worst_verdict) : '');
            byId('dash-map-hover-empty').hidden = Boolean(stats);
            const kicker = byId('dash-map-hover-kicker');
            kicker.classList.remove('is-typing');
            void kicker.offsetWidth;
            if (!reducedMotion()) kicker.classList.add('is-typing');
            card.classList.add('is-visible');
            card.setAttribute('aria-hidden', 'false');
        }

        function setHover(feature, pin) {
            if (globe.hoverFeature && globe.hoverFeature !== feature) {
                globe.countryNodeByNumericId.get(normalizedNumericId(globe.hoverFeature.id))?.classList.remove('is-hovered');
            }
            globe.hoverFeature = feature;
            if (pin) globe.pinnedFeature = feature;
            if (feature) {
                globe.countryNodeByNumericId.get(normalizedNumericId(feature.id))?.classList.add('is-hovered');
                fillCard(feature);
            } else {
                globe.pinnedFeature = null;
                card?.classList.remove('is-visible');
                card?.setAttribute('aria-hidden', 'true');
            }
            requestRender();
        }

        function renderFrame() {
            globe.drawingFrame = null;
            if (!globe) return;
            projection.scale(baseScale * globe.zoom).rotate(globe.rotation);
            const path = globe.path;
            const spherePath = path({type: 'Sphere'}) || '';
            const sphere = byId('dash-map-sphere');
            const atmosphere = byId('dash-map-atmosphere');
            if (sphere) sphere.setAttribute('d', spherePath);
            if (atmosphere) atmosphere.setAttribute('d', spherePath);
            const graticule = byId('dash-map-graticule');
            if (graticule) graticule.setAttribute('d', path(window.d3.geoGraticule10()) || '');
            globe.countryNodes.forEach(({feature, node}) => node.setAttribute('d', path(feature) || ''));

            const center = projection.invert([width / 2, height / 2]);
            globe.markerNodes.forEach(({point, group, circle, halo}) => {
                const projected = projection(point);
                const visible = projected && center && window.d3.geoDistance(point, center) <= Math.PI / 2 + 1e-6;
                group.style.display = visible ? '' : 'none';
                if (!visible) return;
                circle.setAttribute('cx', projected[0]); circle.setAttribute('cy', projected[1]);
                halo.setAttribute('cx', projected[0]); halo.setAttribute('cy', projected[1]);
                const label = group.querySelector('.dash-map-label');
                if (label) {
                    label.setAttribute('x', projected[0] > width / 2 ? projected[0] - 14 : projected[0] + 14);
                    label.setAttribute('y', projected[1] + 4);
                    label.setAttribute('text-anchor', projected[0] > width / 2 ? 'end' : 'start');
                }
            });

            const active = globe.pinnedFeature || globe.hoverFeature;
            if (active && card) {
                const code = COUNTRY_CODES_BY_NUMERIC_ID[normalizedNumericId(active.id)];
                const point = code && COUNTRY_CENTROIDS[code] ? COUNTRY_CENTROIDS[code].slice(0, 2) : window.d3.geoCentroid(active);
                const projected = projection(point);
                const visible = projected && center && window.d3.geoDistance(point, center) <= Math.PI / 2 + 1e-6;
                if (visible) {
                    card.classList.add('is-visible');
                    card.setAttribute('aria-hidden', 'false');
                    const rect = map.parentElement.getBoundingClientRect();
                    const sx = rect.width / width, sy = rect.height / height;
                    const cardWidth = Math.min(230, Math.max(175, rect.width * 0.42));
                    const cardHeight = card.offsetHeight || 150;
                    const x = projected[0] * sx, y = projected[1] * sy;
                    const choices = [
                        {x: x + 26, y: y - cardHeight / 2, side: 'right'},
                        {x: x - cardWidth - 26, y: y - cardHeight / 2, side: 'left'},
                        {x: x - cardWidth / 2, y: y + 26, side: 'bottom'},
                        {x: x - cardWidth / 2, y: y - cardHeight - 26, side: 'top'},
                    ];
                    const fits = choices.find((v) => v.x >= 8 && v.y >= 8 && v.x + cardWidth <= rect.width - 8 && v.y + cardHeight <= rect.height - 8);
                    const side = fits || choices[0];
                    const cx = clamp(side.x, 8, Math.max(8, rect.width - cardWidth - 8));
                    const cy = clamp(side.y, 8, Math.max(8, rect.height - cardHeight - 8));
                    card.style.width = cardWidth + 'px';
                    card.style.transform = 'translate(' + cx + 'px,' + cy + 'px)';
                    if (hoverGraphics) hoverGraphics.style.display = '';
                    const tx = (side.side === 'left' ? cx + cardWidth : side.side === 'right' ? cx : cx + cardWidth / 2) / sx;
                    const ty = (side.side === 'top' ? cy + cardHeight : side.side === 'bottom' ? cy : cy + cardHeight / 2) / sy;
                    leader?.setAttribute('x1', projected[0]); leader?.setAttribute('y1', projected[1]);
                    leader?.setAttribute('x2', tx); leader?.setAttribute('y2', ty);
                    ring?.setAttribute('cx', projected[0]); ring?.setAttribute('cy', projected[1]);
                    crosshair?.setAttribute('transform', 'translate(' + projected[0] + ' ' + projected[1] + ')');
                } else {
                    hoverGraphics.style.display = 'none';
                    card.classList.remove('is-visible');
                    card.setAttribute('aria-hidden', 'true');
                }
            } else if (hoverGraphics) hoverGraphics.style.display = 'none';

            const focused = center && globe.countryFeatures.find((feature) => window.d3.geoContains(feature, center));
            setFocusedFeature(focused || null);
            const zoomIn = byId('dash-map-zoom-in'), zoomOut = byId('dash-map-zoom-out');
            if (zoomIn) zoomIn.disabled = globe.zoom >= 6;
            if (zoomOut) zoomOut.disabled = globe.zoom <= 1;
        }
        globe.renderFrame = renderFrame;

        function lerp(a, b, t) {
            return a + (b - a) * t;
        }

        function lerpRotation(from, to, t) {
            const rawLongitudeDelta = to[0] - from[0];
            const longitudeDelta = ((rawLongitudeDelta + 180) % 360 + 360) % 360 - 180;
            return [
                from[0] + longitudeDelta * t,
                clamp(lerp(from[1], to[1], t), -90, 90),
                lerp(from[2] || 0, to[2] || 0, t),
            ];
        }

        function easeInOutCubic(t) {
            return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
        }

        function cancelViewAnimation() {
            if (globe.animationFrame !== null) window.cancelAnimationFrame(globe.animationFrame);
            globe.animationFrame = null;
        }

        function animateView(targetRotation, targetZoom, duration) {
            cancelViewAnimation();
            targetZoom = clampZoom(targetZoom);
            const animationHelpers = {lerp, lerpRotation, easeInOutCubic};
            const missingAnimationHelper = Object.entries(animationHelpers).find(([, helper]) => typeof helper !== 'function')?.[0];
            if (missingAnimationHelper && !globe.animationFallbackLogged) {
                console.error('Dashboard globe animation helper missing: ' + missingAnimationHelper + '; using instant view changes.');
                globe.animationFallbackLogged = true;
            }
            if (reducedMotion() || duration <= 0 || missingAnimationHelper) {
                globe.rotation = targetRotation;
                globe.rotation[1] = clamp(globe.rotation[1], -90, 90);
                globe.zoom = targetZoom;
                requestRender();
                return;
            }
            const startRotation = globe.rotation.slice();
            const startZoom = globe.zoom;
            const startLogZoom = Math.log(startZoom);
            const targetLogZoom = Math.log(targetZoom);
            const started = performance.now();
            const tick = (now) => {
                const t = clamp((now - started) / duration, 0, 1);
                const eased = easeInOutCubic(t);
                globe.rotation = lerpRotation(startRotation, targetRotation, eased);
                globe.zoom = Math.exp(lerp(startLogZoom, targetLogZoom, eased));
                renderFrame();
                if (t < 1) globe.animationFrame = window.requestAnimationFrame(tick);
                else globe.animationFrame = null;
            };
            globe.animationFrame = window.requestAnimationFrame(tick);
        }

        function focusPoint(point, duration, zoom) {
            if (!Array.isArray(point)) return;
            animateView([-Number(point[0]), clamp(-Number(point[1]), -90, 90), 0], zoom ?? globe.zoom, duration ?? 600);
        }
        function focusFeature(feature) {
            const code = COUNTRY_CODES_BY_NUMERIC_ID[normalizedNumericId(feature.id)];
            focusPoint(code && COUNTRY_CENTROIDS[code] ? COUNTRY_CENTROIDS[code] : window.d3.geoCentroid(feature), 600, 2);
        }
        function setZoom(value, duration) {
            animateView(globe.rotation.slice(), value, duration ?? 240);
        }
        byId('dash-map-zoom-in')?.addEventListener('click', () => setZoom(globe.zoom + 0.5));
        byId('dash-map-zoom-out')?.addEventListener('click', () => setZoom(globe.zoom - 0.5));
        byId('dash-map-zoom-reset')?.addEventListener('click', () => setZoom(1));
        map.addEventListener('wheel', (event) => {
            event.preventDefault();
            setZoom(globe.zoom * Math.exp(-event.deltaY * 0.0015), 180);
        }, {passive: false});

        map.addEventListener('pointerdown', (event) => {
            if (event.pointerType === 'mouse' && event.button !== 0) return;
            cancelViewAnimation();
            globe.pointers.set(event.pointerId, {x: event.clientX, y: event.clientY, lastX: event.clientX, lastY: event.clientY, moved: false});
            map.setPointerCapture(event.pointerId);
            map.parentElement.classList.add('is-dragging');
            if (globe.pointers.size === 2) {
                const points = [...globe.pointers.values()];
                globe.pinchStart = {distance: Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y), zoom: globe.zoom};
                globe.dragPointerId = null;
            } else if (globe.pointers.size === 1) globe.dragPointerId = event.pointerId;
        });
        map.addEventListener('pointermove', (event) => {
            const pointer = globe.pointers.get(event.pointerId);
            if (!pointer) {
                if (event.pointerType === 'mouse') {
                    const node = event.target.closest?.('.dash-map-country');
                    if (node?._dashFeature && node._dashFeature !== globe.hoverFeature) setHover(node._dashFeature, false);
                }
                return;
            }
            pointer.x = event.clientX; pointer.y = event.clientY;
            if (globe.pointers.size > 1 && globe.pinchStart) {
                const points = [...globe.pointers.values()];
                const distance = Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y);
                globe.zoom = clampZoom(globe.pinchStart.zoom * distance / Math.max(1, globe.pinchStart.distance));
                requestRender();
            } else if (globe.dragPointerId === event.pointerId) {
                const dx = event.clientX - pointer.lastX, dy = event.clientY - pointer.lastY;
                pointer.lastX = event.clientX; pointer.lastY = event.clientY;
                if (dx || dy) pointer.moved = true;
                const sensitivity = (180 / (Math.PI * baseScale)) / globe.zoom;
                globe.rotation[0] -= dx * sensitivity;
                globe.rotation[1] = clamp(globe.rotation[1] - dy * sensitivity, -90, 90);
                requestRender();
            }
        });
        const endPointer = (event) => {
            const pointer = globe.pointers.get(event.pointerId);
            if (!pointer) return;
            globe.suppressClick = pointer.moved || globe.pointers.size > 1;
            globe.pointers.delete(event.pointerId);
            globe.pinchStart = null;
            globe.dragPointerId = globe.pointers.size === 1 ? [...globe.pointers.keys()][0] : null;
            if (!globe.pointers.size) {
                map.parentElement.classList.remove('is-dragging');
                if (map.hasPointerCapture(event.pointerId)) map.releasePointerCapture(event.pointerId);
            }
        };
        map.addEventListener('pointerup', endPointer);
        map.addEventListener('pointercancel', endPointer);
        map.addEventListener('lostpointercapture', endPointer);
        map.addEventListener('pointerleave', (event) => {
            if (event.pointerType === 'mouse' && !globe.pinnedFeature) setHover(null, false);
        });
        map.addEventListener('focusin', (event) => {
            const node = event.target.closest?.('.dash-map-country');
            if (node?._dashFeature) setHover(node._dashFeature, false);
        });
        map.addEventListener('focusout', (event) => {
            if (!event.relatedTarget?.closest?.('.dash-map-country') && !globe.pinnedFeature) setHover(null, false);
        });
        map.addEventListener('click', (event) => {
            if (globe.suppressClick) { globe.suppressClick = false; return; }
            const node = event.target.closest?.('.dash-map-country');
            if (node?._dashFeature) {
                if (event.pointerType === 'touch') {
                    if (globe.pinnedFeature === node._dashFeature) setHover(null, false);
                    else setHover(node._dashFeature, true);
                }
                focusFeature(node._dashFeature);
            } else if (globe.pinnedFeature) setHover(null, false);
        });
        map.parentElement.addEventListener('click', (event) => {
            if (globe.pinnedFeature && !event.target.closest?.('.dash-map-country') &&
                !event.target.closest?.('.dash-map-hover-card')) setHover(null, false);
        });
        map.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            const node = event.target.closest?.('.dash-map-country');
            if (!node?._dashFeature) return;
            event.preventDefault();
            focusFeature(node._dashFeature);
        });

        projection.rotate(globe.rotation);
        requestRender();
        fetch('/static/vendor/world/countries-110m.json')
            .then((response) => {
                if (!response.ok) throw new Error('Country geometry is unavailable.');
                return response.json();
            })
            .then((topology) => {
                if (!topology?.objects?.countries) throw new Error('Country geometry is unavailable.');
                const collection = window.topojson.feature(topology, topology.objects.countries);
                if (!Array.isArray(collection?.features)) throw new Error('Country geometry is unavailable.');
                globe.countryFeatures = collection.features;
                globe.countryFeatures.forEach((feature) => {
                    const numericId = normalizedNumericId(feature.id);
                    const title = feature.properties?.name || 'Country';
                    const node = svgElement('path', {
                        class: 'dash-map-land dash-map-country', 'data-n3': numericId,
                        tabindex: '0', role: 'button', 'aria-label': title + '. Select to centre the globe.',
                    });
                    node._dashFeature = feature;
                    countriesGroup.appendChild(node);
                    globe.countryNodes.push({feature, node});
                    globe.featureByNumericId.set(numericId, feature);
                    globe.countryNodeByNumericId.set(numericId, node);
                });
                globe.topologyLoaded = true;
                renderGlobeData();
                requestRender();
            })
            .catch(() => mapError('Country globe data is unavailable.'));

        function renderGlobeData() {
            if (!globe?.topologyLoaded) return;
            globe.countryNodes.forEach(({feature, node}) => {
                const numericId = normalizedNumericId(feature.id);
                const code = COUNTRY_CODES_BY_NUMERIC_ID[numericId];
                const stats = code ? globe.statsByCode.get(code) : null;
                node.classList.remove(
                    'dash-map-country--malicious', 'dash-map-country--phishing',
                    'dash-map-country--suspicious', 'dash-map-country--spam',
                    'dash-map-country--clean', 'dash-map-country--other',
                );
                if (stats) {
                    node.classList.add('dash-map-country--' + countryVerdictClass(stats.worst_verdict));
                    node.setAttribute('aria-label', countryName(code) + ': ' + stats.ips + ' unique IPs, ' +
                        stats.analyses + ' analyses, ' + stats.worst_verdict + '. Select to centre the globe.');
                }
            });
            globe.markersGroup.replaceChildren();
            globe.markerNodes = [];
            globe.statsByCode.forEach((stats, code) => {
                const centroid = COUNTRY_CENTROIDS[code];
                const numericId = COUNTRY_NUMERIC_IDS[code];
                if (!centroid || !globe.featureByNumericId.has(numericId)) return;
                const style = verdictStyle(stats.worst_verdict);
                const radius = Math.max(4, Math.min(9, Math.sqrt(stats.ips) * 1.4));
                const group = svgElement('g', {'aria-hidden': 'true'});
                const halo = svgElement('circle', {r: radius + 4, class: 'dash-map-marker-halo--' + style});
                const circle = svgElement('circle', {r: radius, class: 'dash-map-marker dash-map-marker--' + style});
                group.appendChild(halo); group.appendChild(circle);
                group.appendChild(svgElement('text', {class: 'dash-map-label'}, code + ' ' + stats.ips));
                markersGroup.appendChild(group);
                globe.markerNodes.push({point: centroid.slice(0, 2), group, circle, halo});
            });
            const missingCodes = [...new Set([...globe.statsByCode.keys()].filter((code) =>
                !COUNTRY_NUMERIC_IDS[code] || !globe.featureByNumericId.has(COUNTRY_NUMERIC_IDS[code])
            ))];
            const notMapped = byId('dash-country-not-mapped');
            if (notMapped) notMapped.textContent = 'Not on map: ' + missingCodes.length +
                (missingCodes.length ? ' (' + missingCodes.join(', ') + ')' : '');
            if (!globe.initialViewSet && globe.hasStats) {
                const topCountry = [...globe.statsByCode.values()].sort((a, b) => b.ips - a.ips)[0];
                focusPoint((topCountry && countryCenter(topCountry.code)) || [0, -20], 0, 1);
                globe.initialViewSet = true;
            }
            requestRender();
        }
        globe.renderGlobeData = renderGlobeData;
        globe.focusPoint = focusPoint;
        globe.focusFeature = focusFeature;
    }

    function updateCountryLocations(countryRows, coveredValue, totalValue) {
        const map = byId('dash-country-map');
        const list = byId('dash-country-list');
        const empty = byId('dash-country-empty');
        const coverage = byId('dash-country-coverage');
        if (!map || !list || !empty || !coverage) return;

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
        list.replaceChildren();
        if (globe) {
            globe.statsByCode = new Map(normalizedRows.map((item) => [item.code, item]));
            globe.hasStats = true;
            globe.renderGlobeData?.();
        }

        normalizedRows.slice(0, 8).forEach((item) => {
            const listItem = document.createElement('li');
            listItem.className = 'dash-country-item';
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'dash-country-item-button';
            button.setAttribute('aria-label', `Centre globe on ${countryName(item.code)}`);
            appendText(button, 'span', 'dash-country-name', `${countryName(item.code)} (${item.code})`);
            appendText(button, 'span', 'dash-country-count', `${item.ips} unique IP${item.ips === 1 ? '' : 's'}`);
            appendText(
                button,
                'span',
                `dash-country-verdict dash-country-verdict--${verdictStyle(item.worst_verdict)}`,
                item.worst_verdict,
            );
            button.addEventListener('click', () => {
                const center = countryCenter(item.code);
                if (center) globe?.focusPoint?.(center);
            });
            listItem.appendChild(button);
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
        const pill = appendText(meta, 'span', 'dash-pill dash-pill--danger', `Malicious ${score === null || score === undefined ? '\u2014' : score}`);
        pill.setAttribute('aria-label', `Malicious, score ${score === null || score === undefined ? 'unavailable' : `${score} out of 100`}`);
        appendText(meta, 'time', 'dash-feed-time', formatUtc(item.created_at));
        card.appendChild(meta);

        const indicator = item.ioc || item.filename || item.id || '\u2014';
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

    const THREAT_FEED_ERROR_MESSAGES = {
        auth_key_missing: 'API key not configured',
        http_401: 'API key rejected',
        timeout: 'Provider unreachable',
        network_error: 'Provider unreachable',
        parse_error: 'Provider returned an unexpected response',
        response_too_large: 'Provider returned an unexpected response',
    };

    function threatFeedErrorMessage(code) {
        if (typeof code !== 'string' || !code) return 'Provider status unavailable';
        if (THREAT_FEED_ERROR_MESSAGES[code]) return THREAT_FEED_ERROR_MESSAGES[code];
        if (/^http_\d{3}$/.test(code)) return 'Provider returned an unexpected response';
        return 'Provider status unavailable';
    }

    function formatRelative(value) {
        const date = parseUtc(value);
        if (!date) return formatUtc(value);
        const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
        return `${Math.floor(seconds / 86400)} days ago`;
    }

    function renderThreatFeedSources(sources, container) {
        container.replaceChildren();
        const names = {threatfox: 'ThreatFox', feodo: 'Feodo Tracker'};
        (Array.isArray(sources) ? sources : []).forEach((source) => {
            const row = document.createElement('div');
            row.className = 'dash-threat-source-row';
            const head = document.createElement('div');
            head.className = 'dash-threat-footer-head';
            appendText(head, 'span', 'dash-threat-source-name', names[source?.source] || 'Threat feed');

            const successAt = typeof source?.last_success_at === 'string' ? source.last_success_at : '';
            const successDate = parseUtc(successAt);
            const errorCode = typeof source?.error_code === 'string' ? source.error_code : '';
            let stateText = '';
            let warning = false;
            if (errorCode) {
                stateText = threatFeedErrorMessage(errorCode);
                warning = true;
            } else if (!successAt) {
                stateText = 'Not synced yet';
            } else if (source?.status === 'ok') {
                stateText = successDate && Date.now() - successDate.getTime() <= 8 * 86400000
                    ? 'Up to date'
                    : 'Stale';
                warning = stateText === 'Stale';
            } else {
                stateText = 'Provider status unavailable';
                warning = true;
            }

            if (successAt) {
                const updated = appendText(head, 'time', 'dash-feed-time', `Updated ${formatRelative(successAt)}`);
                updated.setAttribute('datetime', successAt);
                updated.setAttribute('title', formatUtc(successAt));
            }
            row.appendChild(head);
            const staleBadge = stateText === 'Stale';
            const statusClass = staleBadge
                ? 'dash-threat-chip dash-threat-chip--warning'
                : `dash-threat-state${warning ? ' dash-threat-state--warning' : ''}`;
            const status = appendText(row, 'span', statusClass, stateText);
            status.setAttribute('role', 'status');
            if (successAt) status.setAttribute('title', formatUtc(successAt));
            container.appendChild(row);
        });
    }

    function createThreatFeedItem(item) {
        const card = document.createElement('article');
        card.className = 'dash-threat-item';
        const meta = document.createElement('div');
        meta.className = 'dash-threat-meta';
        const sourceNames = {threatfox: 'ThreatFox', feodo: 'Feodo'};
        appendText(meta, 'span', 'dash-threat-chip', sourceNames[item?.source] || 'Threat feed');
        const typeNames = {ip: 'IP', 'ip:port': 'IP:port', domain: 'Domain', url: 'URL', hash: 'Hash', other: 'Other'};
        appendText(meta, 'span', 'dash-threat-type', typeNames[item?.ioc_type] || 'Other');
        card.appendChild(meta);

        const safeIoc = defangIoc(item?.ioc_value, item?.ioc_type);
        const value = appendText(card, 'div', 'dash-threat-ioc', safeIoc);
        value.setAttribute('title', safeIoc);
        value.setAttribute('aria-label', `Defanged indicator: ${safeIoc}`);

        if (typeof item?.malware === 'string' && item.malware.trim()) {
            appendText(card, 'div', 'dash-threat-detail', `Malware: ${item.malware}`);
        }
        if (typeof item?.threat_type === 'string' && item.threat_type.trim()) {
            appendText(card, 'div', 'dash-threat-detail', `Threat type: ${item.threat_type}`);
        }
        const time = appendText(card, 'time', 'dash-threat-detail', `First seen: ${formatUtc(item?.first_seen)}`);
        if (typeof item?.first_seen === 'string' && item.first_seen) time.setAttribute('datetime', item.first_seen);
        if (item?.confidence !== null && item?.confidence !== undefined && Number.isFinite(Number(item.confidence))) {
            appendText(card, 'div', 'dash-threat-detail', `Confidence: ${Number(item.confidence)}%`);
        }
        return card;
    }

    async function fetchThreatFeed() {
        const list = byId('dash-threat-feed-items');
        const sources = byId('dash-threat-feed-sources');
        if (!list || !sources) return;
        try {
            const response = await fetch('/api/dashboard/threat-feed?limit=10');
            if (!response.ok) throw new Error('threat feed unavailable');
            const data = await response.json();
            const items = Array.isArray(data.items) ? data.items : [];
            list.replaceChildren();
            if (!items.length) {
                appendText(list, 'p', 'dash-empty', 'No threat feed data yet');
            } else {
                items.forEach((item) => list.appendChild(createThreatFeedItem(item || {})));
            }
            renderThreatFeedSources(data.sources, sources);
        } catch (_error) {
            list.replaceChildren();
            sources.replaceChildren();
            appendText(list, 'p', 'dash-empty', 'Could not load threat feed');
        }
    }

    const threatFeedSyncButton = byId('dash-threat-feed-sync');
    if (threatFeedSyncButton) {
        threatFeedSyncButton.addEventListener('click', async function () {
            const actionStatus = byId('dash-threat-feed-action-status');
            const originalLabel = 'Sync now';
            threatFeedSyncButton.disabled = true;
            threatFeedSyncButton.textContent = 'Syncing...';
            if (actionStatus) actionStatus.textContent = '';
            try {
                const response = await fetch('/api/dashboard/threat-feed/sync', {method: 'POST'});
                if (response.status === 403) {
                    threatFeedSyncButton.hidden = true;
                    return;
                }
                if (response.status === 409) {
                    if (actionStatus) actionStatus.textContent = 'A sync is already running';
                    return;
                }
                if (!response.ok) {
                    if (actionStatus) actionStatus.textContent = 'Could not sync threat feed';
                    return;
                }
                if (actionStatus) actionStatus.textContent = '';
                await fetchThreatFeed();
            } catch (_error) {
                if (actionStatus) actionStatus.textContent = 'Could not sync threat feed';
            } finally {
                threatFeedSyncButton.disabled = false;
                threatFeedSyncButton.textContent = originalLabel;
            }
        });
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
    initializeGlobe();
    void fetchDashboardStats();
    void fetchMaliciousFeed();
    void fetchThreatFeed();
    // setInterval(fetchDashboardStats, 30000);
});
