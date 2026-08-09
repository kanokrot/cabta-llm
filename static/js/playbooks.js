/* Author: Ugur Ates */
/* Playbooks - Playbook management and execution (playbook.js extracted from playbooks.html) */

function showNotification(msg, type) {
    if (window.BTADashboard && window.BTADashboard.showToast) {
        window.BTADashboard.showToast(msg, type);
    } else {
        alert(msg);
    }
}

var Playbooks = (function () {
    'use strict';

    /* ── Utility: safe text escaping ── */
    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
    function escapeAttr(str) {
        return str.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    /* ── Category assignment ── */
    var CATEGORIES = {
        'threat-intel':       { label: 'Threat Intel',       icon: 'bi-shield-exclamation', keywords: ['threat','intel','ioc','indicator','reputation','osint','cve','vulnerability','enrich'] },
        'incident-response':  { label: 'Incident Response',  icon: 'bi-exclamation-triangle', keywords: ['incident','response','triage','alert','escalat','contain','remediat','isolat'] },
        'malware-analysis':   { label: 'Malware Analysis',   icon: 'bi-bug', keywords: ['malware','virus','trojan','ransomware','sandbox','reverse','sample','binary','hash'] },
        'phishing':           { label: 'Phishing',           icon: 'bi-envelope-exclamation', keywords: ['phish','email','spam','spoof','header','dmarc','spf','dkim','url'] },
        'forensics':          { label: 'Forensics',          icon: 'bi-fingerprint', keywords: ['forensic','memory','disk','artifact','evidence','timeline','log','pcap','network forensic'] }
    };

    function getPlaybookCategory(pb) {
        // 1. Prefer explicit category from data if valid
        if (pb && pb.category && CATEGORIES[pb.category]) {
            return pb.category;
        }
        // 2. Fallback to keyword-based detection
        var text = ((pb.name || '') + ' ' + (pb.description || '')).toLowerCase();
        var bestCat = 'general';
        var bestScore = 0;
        for (var cat in CATEGORIES) {
            var score = 0;
            CATEGORIES[cat].keywords.forEach(function(kw) {
                if (text.indexOf(kw) !== -1) score++;
            });
            if (score > bestScore) {
                bestScore = score;
                bestCat = cat;
            }
        }
        return bestCat;
    }

    function getCategoryInfo(cat) {
        if (CATEGORIES[cat]) return CATEGORIES[cat];
        return { label: 'General', icon: 'bi-journal-code' };
    }

    /* ── Duration estimate (heuristic: ~30s per step) ── */
    function estimateDuration(stepCount) {
        if (!stepCount || stepCount <= 0) return '< 1 min';
        var totalSec = stepCount * 30;
        if (totalSec < 60) return '< 1 min';
        var mins = Math.ceil(totalSec / 60);
        return '~' + mins + ' min';
    }

    /* ── Last run from localStorage ── */
    function getLastRun(playbookId) {
        try {
            var data = JSON.parse(localStorage.getItem('pb_lastrun') || '{}');
            return data[playbookId] || null;
        } catch (e) { return null; }
    }
    function setLastRun(playbookId) {
        try {
            var data = JSON.parse(localStorage.getItem('pb_lastrun') || '{}');
            data[playbookId] = new Date().toISOString();
            localStorage.setItem('pb_lastrun', JSON.stringify(data));
        } catch (e) { /* ignore */ }
    }
    function formatLastRun(iso) {
        if (!iso) return null;
        try {
            var d = new Date(iso);
            var now = new Date();
            var diff = now - d;
            if (diff < 60000) return 'just now';
            if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
            if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
            return d.toLocaleDateString();
        } catch (e) { return null; }
    }

    /* ── Collect unique tools from steps ── */
    function collectTools(steps) {
        var tools = {};
        (steps || []).forEach(function(s) {
            var t = s.tool || s.type;
            if (t) tools[t] = true;
        });
        return Object.keys(tools);
    }

    /* ── Tool icon mapping ── */
    function getToolIcon(toolName) {
        if (!toolName) return 'bi-wrench';
        var t = toolName.toLowerCase();
        if (t.indexOf('virus') !== -1 || t.indexOf('malware') !== -1 || t.indexOf('sandbox') !== -1) return 'bi-bug';
        if (t.indexOf('email') !== -1 || t.indexOf('phish') !== -1) return 'bi-envelope';
        if (t.indexOf('dns') !== -1 || t.indexOf('whois') !== -1 || t.indexOf('domain') !== -1) return 'bi-globe';
        if (t.indexOf('ip') !== -1 || t.indexOf('geo') !== -1 || t.indexOf('network') !== -1) return 'bi-hdd-network';
        if (t.indexOf('hash') !== -1 || t.indexOf('file') !== -1) return 'bi-file-earmark-binary';
        if (t.indexOf('alert') !== -1 || t.indexOf('siem') !== -1) return 'bi-bell';
        if (t.indexOf('report') !== -1 || t.indexOf('notify') !== -1) return 'bi-megaphone';
        if (t.indexOf('block') !== -1 || t.indexOf('firewall') !== -1 || t.indexOf('isolat') !== -1) return 'bi-shield-x';
        if (t.indexOf('enrich') !== -1 || t.indexOf('lookup') !== -1 || t.indexOf('search') !== -1) return 'bi-search';
        if (t.indexOf('parse') !== -1 || t.indexOf('extract') !== -1) return 'bi-funnel';
        return 'bi-wrench';
    }

    /* ── Stats update ── */
    var allPlaybooksData = [];

    function updateStats(playbooks) {
        var totalSteps = 0;
        var allTools = {};
        var cats = {};
        playbooks.forEach(function(pb) {
            var steps = pb.steps || [];
            var sc = steps.length || pb.step_count || 0;
            totalSteps += sc;
            // Prefer a pre-computed `tools` list from the API (list endpoint may not
            // include full step bodies); fall back to scanning steps if present.
            if (Array.isArray(pb.tools)) {
                pb.tools.forEach(function(t) { if (t) allTools[t] = true; });
            } else {
                steps.forEach(function(s) {
                    var t = s.tool || s.type;
                    if (t) allTools[t] = true;
                });
            }
            var cat = getPlaybookCategory(pb);
            cats[cat] = true;
        });
        document.getElementById('statTotalPlaybooks').textContent = playbooks.length;
        document.getElementById('statTotalSteps').textContent = totalSteps;
        document.getElementById('statUniqueTools').textContent = Object.keys(allTools).length;
        document.getElementById('statCategories').textContent = Object.keys(cats).length;
    }

    /* ── Search & filter state ── */
    var currentFilter = 'all';
    var currentSearch = '';

    function applyFilters() {
        var cols = document.querySelectorAll('#playbookGrid .playbook-col');
        var searchLower = currentSearch.toLowerCase();
        cols.forEach(function(col) {
            var name = (col.getAttribute('data-pb-name') || '').toLowerCase();
            var desc = (col.getAttribute('data-pb-desc') || '').toLowerCase();
            var cat = col.getAttribute('data-pb-category') || 'general';

            var matchSearch = !searchLower || name.indexOf(searchLower) !== -1 || desc.indexOf(searchLower) !== -1;
            var matchCat = currentFilter === 'all' || cat === currentFilter;

            col.style.display = (matchSearch && matchCat) ? '' : 'none';
        });
    }

    /* ── Filter button clicks ── */
    document.getElementById('categoryFilters').addEventListener('click', function(e) {
        var btn = e.target.closest('.filter-btn');
        if (!btn) return;
        document.querySelectorAll('#categoryFilters .filter-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        currentFilter = btn.getAttribute('data-category');
        applyFilters();
    });

    /* ── Search input ── */
    document.getElementById('playbookSearchInput').addEventListener('input', function(e) {
        currentSearch = e.target.value.trim();
        applyFilters();
    });

    /* ── Build a single playbook card using safe DOM methods ── */
    function buildCard(pb) {
        var pbId = pb.id || pb.name || '';
        var pbName = pb.name || 'Untitled';
        var pbDesc = pb.description || 'No description.';
        var steps = pb.steps || [];
        var stepCount = steps.length || pb.step_count || 0;
        var tt = (pb.trigger_type || pb.trigger || 'manual').toLowerCase();
        var cat = getPlaybookCategory(pb);
        var catInfo = getCategoryInfo(cat);
        var tools = Array.isArray(pb.tools) ? pb.tools : collectTools(steps);
        var lastRun = formatLastRun(getLastRun(pbId));

        var col = document.createElement('div');
        col.className = 'col-xl-4 col-md-6 playbook-col';
        col.setAttribute('data-pb-name', pbName);
        col.setAttribute('data-pb-desc', pbDesc);
        col.setAttribute('data-pb-category', cat);

        var card = document.createElement('div');
        card.className = 'playbook-card';

        // Title
        var titleDiv = document.createElement('div');
        titleDiv.className = 'pb-title';
        var titleIcon = document.createElement('i');
        titleIcon.className = 'bi ' + catInfo.icon + ' me-2 text-accent';
        titleDiv.appendChild(titleIcon);
        titleDiv.appendChild(document.createTextNode(pbName));
        card.appendChild(titleDiv);

        // Description
        var descDiv = document.createElement('div');
        descDiv.className = 'pb-desc';
        descDiv.textContent = pbDesc;
        card.appendChild(descDiv);

        // Meta row
        var meta = document.createElement('div');
        meta.className = 'pb-meta';

        var trigBadge = document.createElement('span');
        trigBadge.className = 'trigger-badge trigger-' + tt;
        trigBadge.textContent = tt;
        meta.appendChild(trigBadge);

        var catBadge = document.createElement('span');
        catBadge.className = 'category-badge cat-' + cat;
        catBadge.textContent = catInfo.label;
        meta.appendChild(catBadge);

        var stepLabel = document.createElement('small');
        stepLabel.className = 'text-muted';
        stepLabel.textContent = stepCount + ' steps';
        meta.appendChild(stepLabel);

        if (tools.length > 0) {
            var toolLabel = document.createElement('small');
            toolLabel.className = 'text-muted';
            var toolLabelIcon = document.createElement('i');
            toolLabelIcon.className = 'bi bi-wrench me-1';
            toolLabel.appendChild(toolLabelIcon);
            toolLabel.appendChild(document.createTextNode(tools.length + ' tools'));
            meta.appendChild(toolLabel);
        }

        var durSpan = document.createElement('span');
        durSpan.className = 'duration-estimate';
        var durIcon = document.createElement('i');
        durIcon.className = 'bi bi-clock me-1';
        durSpan.appendChild(durIcon);
        durSpan.appendChild(document.createTextNode(estimateDuration(stepCount)));
        meta.appendChild(durSpan);

        card.appendChild(meta);

        // Last run
        if (lastRun) {
            var lrDiv = document.createElement('div');
            lrDiv.className = 'last-run-info';
            var lrIcon = document.createElement('i');
            lrIcon.className = 'bi bi-arrow-repeat me-1';
            lrDiv.appendChild(lrIcon);
            lrDiv.appendChild(document.createTextNode('Last run: ' + lastRun));
            card.appendChild(lrDiv);
        }

        // Action buttons
        var actions = document.createElement('div');
        actions.className = 'd-flex gap-2 mt-auto';

        var viewBtn = document.createElement('button');
        viewBtn.className = 'btn btn-outline-secondary btn-sm flex-grow-1 playbook-view-btn';
        viewBtn.setAttribute('data-playbook-id', pbId);
        var vIcon = document.createElement('i');
        vIcon.className = 'bi bi-eye me-1';
        viewBtn.appendChild(vIcon);
        viewBtn.appendChild(document.createTextNode('View'));
        actions.appendChild(viewBtn);

        var runBtn = document.createElement('button');
        runBtn.className = 'btn btn-accent btn-sm flex-grow-1 playbook-run-btn';
        runBtn.setAttribute('data-playbook-id', pbId);
        runBtn.setAttribute('data-playbook-name', pbName);
        var rIcon = document.createElement('i');
        rIcon.className = 'bi bi-play-fill me-1';
        runBtn.appendChild(rIcon);
        runBtn.appendChild(document.createTextNode('Run'));
        actions.appendChild(runBtn);

        card.appendChild(actions);
        col.appendChild(card);
        return col;
    }

    /* ── Event delegation for run/view buttons ── */
    document.getElementById('playbookGrid').addEventListener('click', function (e) {
        var runBtn = e.target.closest('.playbook-run-btn');
        if (runBtn) {
            var playbookId = runBtn.getAttribute('data-playbook-id');
            var playbookName = runBtn.getAttribute('data-playbook-name');
            openRunModal(playbookId, playbookName);
            return;
        }

        var viewBtn = e.target.closest('.playbook-view-btn');
        if (viewBtn) {
            var id = viewBtn.getAttribute('data-playbook-id');
            viewPlaybook(id);
        }
    });

    /* ── Open run modal with auto-populated params ── */
    function openRunModal(playbookId, playbookName) {
        document.getElementById('runPlaybookId').value = playbookId;
        document.getElementById('runPlaybookTitle').textContent = 'Run: ' + playbookName;
        document.getElementById('runPlaybookDesc').textContent = '';
        document.getElementById('playbookParams').value = '';
        var container = document.getElementById('runParamFieldsContainer');
        while (container.firstChild) container.removeChild(container.firstChild);
        document.getElementById('runParamsFallback').style.display = '';

        var modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('runPlaybookModal'));
        modal.show();

        // Try to fetch playbook details to auto-populate param fields
        fetch('/api/playbooks/' + encodeURIComponent(playbookId))
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(data) {
            if (!data) return;
            if (data.description) {
                document.getElementById('runPlaybookDesc').textContent = data.description;
            }
            var inputParams = data.input_params || data.inputs || data.parameters || null;
            if (inputParams && typeof inputParams === 'object') {
                var keys = Object.keys(inputParams);
                if (keys.length > 0) {
                    document.getElementById('runParamsFallback').style.display = 'none';
                    while (container.firstChild) container.removeChild(container.firstChild);

                    keys.forEach(function(key) {
                        var paramDef = inputParams[key];
                        var isObj = paramDef && typeof paramDef === 'object';
                        var desc = isObj ? (paramDef.description || '') : String(paramDef || '');
                        var required = isObj ? (paramDef.required || false) : false;
                        var defaultVal = isObj ? (paramDef.default || '') : '';

                        var fieldDiv = document.createElement('div');
                        fieldDiv.className = 'run-param-field';

                        var label = document.createElement('label');
                        label.className = 'form-label';
                        label.textContent = key;
                        if (required) {
                            var reqSpan = document.createElement('span');
                            reqSpan.className = 'text-danger ms-1';
                            reqSpan.textContent = '*';
                            label.appendChild(reqSpan);
                        }
                        fieldDiv.appendChild(label);

                        var input = document.createElement('input');
                        input.type = 'text';
                        input.className = 'form-control form-control-sm';
                        input.setAttribute('data-param-key', key);
                        input.setAttribute('data-param-required', required ? 'true' : 'false');
                        input.placeholder = defaultVal || key;
                        if (defaultVal) input.value = defaultVal;
                        fieldDiv.appendChild(input);

                        if (desc) {
                            var helpText = document.createElement('div');
                            helpText.className = 'form-text';
                            helpText.textContent = desc;
                            fieldDiv.appendChild(helpText);
                        }

                        container.appendChild(fieldDiv);
                    });
                }
            }
        })
        .catch(function() { /* fallback to raw JSON */ });
    }

    /* ── Execute playbook ── */
    document.getElementById('executePlaybookBtn').addEventListener('click', function () {
        var playbookId = document.getElementById('runPlaybookId').value;
        var btn = document.getElementById('executePlaybookBtn');
        var params = {};

        // Collect from dynamic fields if present
        var dynamicFields = document.querySelectorAll('#runParamFieldsContainer input[data-param-key]');
        if (dynamicFields.length > 0) {
            var valid = true;
            dynamicFields.forEach(function(input) {
                var key = input.getAttribute('data-param-key');
                var required = input.getAttribute('data-param-required') === 'true';
                var val = input.value.trim();
                if (required && !val) {
                    input.classList.add('is-invalid');
                    valid = false;
                } else {
                    input.classList.remove('is-invalid');
                }
                if (val) params[key] = val;
            });
            if (!valid) {
                showNotification('Please fill in all required parameters.', 'error');
                return;
            }
        } else {
            // Fallback to raw JSON
            var paramsText = document.getElementById('playbookParams').value.trim();
            if (paramsText) {
                try {
                    params = JSON.parse(paramsText);
                } catch (e) {
                    showNotification('Invalid JSON parameters', 'error');
                    return;
                }
            }
        }

        btn.disabled = true;
        btn.textContent = 'Starting...';

        setLastRun(playbookId);

        var runController = new AbortController();
        var runTimeout = setTimeout(function () { runController.abort(); }, 15000);

        fetch('/api/playbooks/' + encodeURIComponent(playbookId) + '/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
            signal: runController.signal
        })
        .then(function (r) {
            clearTimeout(runTimeout);
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (data) {
            btn.disabled = false;
            btn.textContent = 'Execute';
            var modalEl = document.getElementById('runPlaybookModal');
            var modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();

            if (data.session_id) {
                window.location.href = '/agent/chat?session=' + encodeURIComponent(data.session_id);
            } else {
                showNotification('Playbook started successfully.', 'success');
            }
        })
        .catch(function (err) {
            clearTimeout(runTimeout);
            btn.disabled = false;
            btn.textContent = 'Execute';
            var msg = err.name === 'AbortError' ? 'Request timed out.' : err.message;
            showNotification('Failed: ' + msg, 'error');
        });
    });

    /* ── View playbook detail with enhanced flowchart ── */
    var currentViewPlaybookId = null;

    function viewPlaybook(playbookId) {
        currentViewPlaybookId = playbookId;
        var modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('viewPlaybookModal'));
        var body = document.getElementById('viewPlaybookBody');
        body.textContent = 'Loading...';
        var runBtnFooter = document.getElementById('viewModalRunBtn');
        runBtnFooter.style.display = 'none';
        modal.show();

        var viewController = new AbortController();
        var viewTimeout = setTimeout(function () { viewController.abort(); }, 15000);

        fetch('/api/playbooks/' + encodeURIComponent(playbookId), { signal: viewController.signal })
        .then(function (r) {
            clearTimeout(viewTimeout);
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function (data) {
            while (body.firstChild) body.removeChild(body.firstChild);

            var pbName = data.name || playbookId;
            var cat = getPlaybookCategory(data);
            var catInfo = getCategoryInfo(cat);

            // Update modal title
            var titleEl = document.getElementById('viewPlaybookTitle');
            while (titleEl.firstChild) titleEl.removeChild(titleEl.firstChild);
            var titleIcon = document.createElement('i');
            titleIcon.className = 'bi ' + catInfo.icon + ' me-2 text-accent';
            titleEl.appendChild(titleIcon);
            titleEl.appendChild(document.createTextNode(pbName));

            // Category banner
            var banner = document.createElement('div');
            banner.className = 'view-modal-banner banner-' + cat;
            var bannerIconWrap = document.createElement('div');
            bannerIconWrap.className = 'banner-icon';
            var bannerIcon = document.createElement('i');
            bannerIcon.className = 'bi ' + catInfo.icon;
            bannerIconWrap.appendChild(bannerIcon);
            banner.appendChild(bannerIconWrap);
            var bannerText = document.createElement('div');
            var bannerTitle = document.createElement('div');
            bannerTitle.style.cssText = 'font-weight:600;color:var(--text-primary);';
            bannerTitle.textContent = pbName;
            bannerText.appendChild(bannerTitle);
            var bannerSub = document.createElement('div');
            bannerSub.style.cssText = 'font-size:0.82rem;color:var(--text-secondary);';
            bannerSub.textContent = catInfo.label + ' Playbook';
            bannerText.appendChild(bannerSub);
            banner.appendChild(bannerText);
            body.appendChild(banner);

            // Description
            var desc = document.createElement('p');
            desc.className = 'text-muted';
            desc.textContent = pbDesc;
            body.appendChild(desc);

            // Trigger & category meta
            var metaDiv = document.createElement('div');
            metaDiv.className = 'd-flex gap-3 mb-3 flex-wrap align-items-center';
            var tt = (data.trigger_type || 'manual').toLowerCase();
            var trigBadge = document.createElement('span');
            trigBadge.className = 'trigger-badge trigger-' + tt;
            trigBadge.textContent = 'Trigger: ' + tt;
            metaDiv.appendChild(trigBadge);
            var catBadge = document.createElement('span');
            catBadge.className = 'category-badge cat-' + cat;
            catBadge.textContent = catInfo.label;
            metaDiv.appendChild(catBadge);
            body.appendChild(metaDiv);

            // Input parameters section
            var inputParams = data.input_params || data.inputs || data.parameters || null;
            if (inputParams && typeof inputParams === 'object' && Object.keys(inputParams).length > 0) {
                var paramSection = document.createElement('div');
                paramSection.className = 'input-params-section';
                var paramTitle = document.createElement('h6');
                paramTitle.className = 'mb-2';
                var paramTitleIcon = document.createElement('i');
                paramTitleIcon.className = 'bi bi-sliders me-1 text-accent';
                paramTitle.appendChild(paramTitleIcon);
                paramTitle.appendChild(document.createTextNode('Input Parameters'));
                paramSection.appendChild(paramTitle);

                Object.keys(inputParams).forEach(function(key) {
                    var paramDef = inputParams[key];
                    var isObj = paramDef && typeof paramDef === 'object';
                    var paramDescText = isObj ? (paramDef.description || '') : String(paramDef || '');
                    var required = isObj ? paramDef.required : false;

                    var item = document.createElement('div');
                    item.className = 'param-item';
                    var nameSpan = document.createElement('span');
                    nameSpan.className = 'param-name';
                    nameSpan.textContent = key;
                    item.appendChild(nameSpan);
                    if (required) {
                        var reqBadge = document.createElement('span');
                        reqBadge.className = 'param-required';
                        reqBadge.textContent = 'required';
                        item.appendChild(reqBadge);
                    }
                    if (paramDescText) {
                        var descSpan = document.createElement('span');
                        descSpan.className = 'param-desc';
                        descSpan.textContent = paramDescText;
                        item.appendChild(descSpan);
                    }
                    paramSection.appendChild(item);
                });
                body.appendChild(paramSection);
            }

            // Steps flowchart
            var steps = data.steps || [];
            if (steps.length > 0) {
                var stepsHeading = document.createElement('h6');
                stepsHeading.className = 'mb-3';
                var stepsHeadingIcon = document.createElement('i');
                stepsHeadingIcon.className = 'bi bi-diagram-3 me-1 text-accent';
                stepsHeading.appendChild(stepsHeadingIcon);
                stepsHeading.appendChild(document.createTextNode('Steps (' + steps.length + ')'));
                body.appendChild(stepsHeading);

                var stepsContainer = document.createElement('div');
                stepsContainer.className = 'playbook-steps';

                steps.forEach(function (s, i) {
                    var hasCondition = s.condition || s.when;
                    var hasLoop = s.for_each || s.loop;

                    var stepDiv = document.createElement('div');
                    stepDiv.className = 'playbook-step';
                    if (hasCondition) stepDiv.classList.add('step-condition');
                    if (hasLoop) stepDiv.classList.add('step-loop');

                    // Step number
                    var numDiv = document.createElement('div');
                    numDiv.className = 'step-num';
                    numDiv.appendChild(document.createTextNode('Step ' + (i + 1)));
                    if (hasCondition) {
                        var condBadge = document.createElement('span');
                        condBadge.className = 'step-indicator-badge step-indicator-condition';
                        var condIcon = document.createElement('i');
                        condIcon.className = 'bi bi-signpost-split me-1';
                        condBadge.appendChild(condIcon);
                        condBadge.appendChild(document.createTextNode('Condition'));
                        numDiv.appendChild(condBadge);
                    }
                    if (hasLoop) {
                        var loopBadge = document.createElement('span');
                        loopBadge.className = 'step-indicator-badge step-indicator-loop';
                        var loopIcon = document.createElement('i');
                        loopIcon.className = 'bi bi-arrow-repeat me-1';
                        loopBadge.appendChild(loopIcon);
                        loopBadge.appendChild(document.createTextNode('Loop'));
                        numDiv.appendChild(loopBadge);
                    }
                    stepDiv.appendChild(numDiv);

                    // Step name
                    var nameDiv = document.createElement('div');
                    nameDiv.className = 'step-name';
                    nameDiv.textContent = s.name || s.action || 'Step ' + (i + 1);
                    stepDiv.appendChild(nameDiv);

                    // Tool
                    if (s.tool || s.type) {
                        var toolDiv = document.createElement('div');
                        toolDiv.className = 'step-tool';
                        var toolIcon = document.createElement('i');
                        toolIcon.className = 'bi ' + getToolIcon(s.tool || s.type) + ' me-1';
                        toolDiv.appendChild(toolIcon);
                        toolDiv.appendChild(document.createTextNode(s.tool || s.type));
                        stepDiv.appendChild(toolDiv);
                    }

                    // Description
                    if (s.description) {
                        var descDiv = document.createElement('div');
                        descDiv.className = 'text-muted small mt-1';
                        descDiv.textContent = s.description;
                        stepDiv.appendChild(descDiv);
                    }

                    // Condition detail
                    if (s.condition || s.when) {
                        var condEl = document.createElement('small');
                        condEl.className = 'd-block mt-1';
                        condEl.style.cssText = 'color:#fbbf24;font-size:0.75rem;';
                        var condElIcon = document.createElement('i');
                        condElIcon.className = 'bi bi-signpost-split me-1';
                        condEl.appendChild(condElIcon);
                        condEl.appendChild(document.createTextNode('Condition: ' + String(s.condition || s.when)));
                        stepDiv.appendChild(condEl);
                    }

                    // for_each detail
                    if (s.for_each) {
                        var feEl = document.createElement('small');
                        feEl.className = 'd-block mt-1';
                        feEl.style.cssText = 'color:#a78bfa;font-size:0.75rem;';
                        var feIcon = document.createElement('i');
                        feIcon.className = 'bi bi-arrow-repeat me-1';
                        feEl.appendChild(feIcon);
                        feEl.appendChild(document.createTextNode('for_each: ' + String(s.for_each)));
                        stepDiv.appendChild(feEl);
                    }

                    // Params
                    if (s.params) {
                        var pEl = document.createElement('small');
                        pEl.className = 'text-muted d-block mt-1';
                        pEl.style.cssText = 'font-size:0.72rem;font-family:monospace;';
                        pEl.textContent = 'params: ' + JSON.stringify(s.params);
                        stepDiv.appendChild(pEl);
                    }

                    stepsContainer.appendChild(stepDiv);
                });

                body.appendChild(stepsContainer);
            } else {
                var noSteps = document.createElement('p');
                noSteps.className = 'text-muted';
                noSteps.textContent = 'No steps defined.';
                body.appendChild(noSteps);
            }

            // Tool coverage summary
            var tools = collectTools(steps);
            if (tools.length > 0) {
                var toolSection = document.createElement('div');
                toolSection.className = 'tool-coverage-section';
                var toolTitle = document.createElement('h6');
                toolTitle.className = 'mb-2';
                var toolTitleIcon = document.createElement('i');
                toolTitleIcon.className = 'bi bi-wrench-adjustable me-1 text-accent';
                toolTitle.appendChild(toolTitleIcon);
                toolTitle.appendChild(document.createTextNode('Tool Coverage (' + tools.length + ' unique)'));
                toolSection.appendChild(toolTitle);

                var chipWrap = document.createElement('div');
                tools.forEach(function(t) {
                    var chip = document.createElement('span');
                    chip.className = 'tool-chip';
                    var chipIcon = document.createElement('i');
                    chipIcon.className = 'bi ' + getToolIcon(t);
                    chip.appendChild(chipIcon);
                    chip.appendChild(document.createTextNode(t));
                    chipWrap.appendChild(chip);
                });
                toolSection.appendChild(chipWrap);
                body.appendChild(toolSection);
            }

            // Show "Run this Playbook" button in footer
            runBtnFooter.style.display = '';
            runBtnFooter.setAttribute('data-playbook-id', playbookId);
            runBtnFooter.setAttribute('data-playbook-name', pbName);
        })
        .catch(function (err) {
            clearTimeout(viewTimeout);
            while (body.firstChild) body.removeChild(body.firstChild);
            var errDiv = document.createElement('div');
            errDiv.className = 'text-danger py-3';
            errDiv.textContent = err.name === 'AbortError' ? 'Error: request timed out.' : 'Error: ' + err.message;
            body.appendChild(errDiv);
        });
    }

    /* ── "Run this Playbook" button in view modal ── */
    document.getElementById('viewModalRunBtn').addEventListener('click', function() {
        var pbId = this.getAttribute('data-playbook-id');
        var pbName = this.getAttribute('data-playbook-name');
        // Close view modal
        var viewModalEl = document.getElementById('viewPlaybookModal');
        var viewModal = bootstrap.Modal.getInstance(viewModalEl);
        if (viewModal) viewModal.hide();
        // Open run modal after a short delay to let the view modal close
        setTimeout(function() {
            openRunModal(pbId, pbName);
        }, 300);
    });

    /* ── Fetch playbooks via API (for dynamic refresh) ── */
    function loadPlaybooks() {
        fetch('/api/playbooks')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var playbooks = data.playbooks || data || [];
            allPlaybooksData = playbooks;
            var grid = document.getElementById('playbookGrid');
            while (grid.firstChild) grid.removeChild(grid.firstChild);

            if (!playbooks.length) {
                var empty = document.createElement('div');
                empty.className = 'col-12';
                var emptyCard = document.createElement('div');
                emptyCard.className = 'card';
                var emptyBody = document.createElement('div');
                emptyBody.className = 'card-body text-center py-5 text-muted';
                var emptyIcon = document.createElement('i');
                emptyIcon.className = 'bi bi-journal-x fs-1 d-block mb-2 opacity-50';
                emptyBody.appendChild(emptyIcon);
                emptyBody.appendChild(document.createTextNode('No playbooks available.'));
                emptyCard.appendChild(emptyBody);
                empty.appendChild(emptyCard);
                grid.appendChild(empty);
                updateStats([]);
                return;
            }

            playbooks.forEach(function(pb) {
                grid.appendChild(buildCard(pb));
            });

            updateStats(playbooks);
            applyFilters();
        })
        .catch(function(err) {
            showNotification('Failed to refresh: ' + err.message, 'error');
        });
    }

    /* ── Refresh stats bar only, without rebuilding server-rendered cards ──
       Fixes: stats bar showing 0/0/0/0 on first load because the initial
       branch below calls enhanceServerRenderedCards() (which only patches
       card DOM) instead of loadPlaybooks() (which calls updateStats()). */
    function refreshStatsOnly() {
        fetch('/api/playbooks')
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(data) {
            if (!data) return;
            var playbooks = data.playbooks || data || [];
            allPlaybooksData = playbooks;
            updateStats(playbooks);
        })
        .catch(function(err) {
            console.warn('[PLAYBOOK] Failed to refresh stats:', err);
        });
    }

    /* ── Enhance server-rendered cards on initial load ── */
    function enhanceServerRenderedCards() {
        var cols = document.querySelectorAll('#playbookGrid .playbook-col');
        allPlaybooksData.forEach(function(pb) {
            var col = document.querySelector(`[data-pb-id="${pb.id}"]`);
            if (!col) return;

            var cat = getPlaybookCategory(pb);
            col.setAttribute('data-pb-category', cat);

            // Add category badge and extra meta to existing cards
            var metaDiv = col.querySelector('.pb-meta');
            if (metaDiv && !metaDiv.querySelector('.category-badge')) {
                var catInfo = getCategoryInfo(cat);
                var badge = document.createElement('span');
                badge.className = 'category-badge cat-' + cat;
                badge.textContent = catInfo.label;
                // Insert category badge after trigger badge
                var triggerBadge = metaDiv.querySelector('.trigger-badge');
                if (triggerBadge && triggerBadge.nextSibling) {
                    metaDiv.insertBefore(badge, triggerBadge.nextSibling);
                } else {
                    metaDiv.appendChild(badge);
                }

                // Replace card icon
                var titleIcon = col.querySelector('.pb-title i');
                if (titleIcon) {
                    titleIcon.className = 'bi ' + catInfo.icon + ' me-2 text-accent';
                }
            }

            // Add last run info (if not already there)
            if (!col.querySelector('.last-run-info')) {
                var lastRun = formatLastRun(getLastRun(pb.id));
                if (lastRun) {
                    var lrDiv = document.createElement('div');
                    lrDiv.className = 'last-run-info';
                    var lrIcon = document.createElement('i');
                    lrIcon.className = 'bi bi-arrow-repeat me-1';
                    lrDiv.appendChild(lrIcon);
                    lrDiv.appendChild(document.createTextNode('Last run: ' + lastRun));
                    var actions = col.querySelector('.d-flex.gap-2');
                    if (actions) {
                        actions.parentNode.insertBefore(lrDiv, actions);
                    }
                }
            }
        });
    }

    // Auto-load from API if server-rendered list is empty, otherwise enhance existing
    var grid = document.getElementById('playbookGrid');
    if (grid && grid.querySelectorAll('.playbook-card').length === 0) {
        loadPlaybooks();
    } else {
        enhanceServerRenderedCards();
        refreshStatsOnly();
    }

    return {
        loadPlaybooks: loadPlaybooks
    };
})();