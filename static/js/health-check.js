(function () {
    var button = document.getElementById('health-check-button');
    var modalElement = document.getElementById('healthCheckModal');
    var content = document.getElementById('healthCheckContent');

    if (!button || !modalElement || !content || !window.bootstrap) return;

    var modal = bootstrap.Modal.getOrCreateInstance(modalElement);

    function showMessage(message) {
        content.replaceChildren();
        var messageElement = document.createElement('p');
        messageElement.className = 'mb-0';
        messageElement.textContent = message;
        content.appendChild(messageElement);
    }

    function label(value) {
        var acronyms = {
            llm: 'LLM',
            mcp: 'MCP',
            ioc: 'IOC',
            sqlite: 'SQLite',
            chromadb: 'ChromaDB',
            vllm: 'vLLM'
        };
        var raw = String(value || '');
        if (acronyms[raw.toLowerCase()]) return acronyms[raw.toLowerCase()];
        return raw.replace(/_/g, ' ').replace(/^\w/, function (letter) {
            return letter.toUpperCase();
        });
    }

    function statusClass(status) {
        if (status === 'healthy') return 'text-success';
        if (status === 'degraded') return 'text-warning';
        if (status === 'unhealthy') return 'text-danger';
        return 'text-secondary';
    }

    function statusBadge(status) {
        var badge = document.createElement('span');
        badge.className = 'badge rounded-pill ' + (statusClass(status) === 'text-success'
            ? 'bg-success'
            : statusClass(status) === 'text-warning'
                ? 'bg-warning text-dark'
                : statusClass(status) === 'text-danger'
                    ? 'bg-danger'
                    : 'bg-secondary');
        badge.textContent = label(status || 'unknown');
        return badge;
    }

    function addMetaRow(parent, name, value) {
        var row = document.createElement('div');
        row.className = 'd-flex justify-content-between gap-3 py-1';
        var key = document.createElement('span');
        key.className = 'text-muted';
        key.textContent = name;
        var text = document.createElement('span');
        text.className = 'text-end';
        text.textContent = typeof value === 'boolean'
            ? (value ? 'Yes' : 'No')
            : (value == null ? '' : String(value));
        row.appendChild(key);
        row.appendChild(text);
        parent.appendChild(row);
    }

    function formatUptime(seconds) {
        var total = Math.max(0, Math.floor(Number(seconds) || 0));
        var days = Math.floor(total / 86400);
        var hours = Math.floor((total % 86400) / 3600);
        var minutes = Math.floor((total % 3600) / 60);
        return days + 'd ' + hours + 'h ' + minutes + 'm';
    }

    function isSensitiveKey(key) {
        return /url|key|token|secret|header/i.test(String(key));
    }

    function appendNestedRows(parent, name, value) {
        if (isSensitiveKey(name)) return;
        if (String(name).toLowerCase() === 'name') return;
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            var group = document.createElement('div');
            group.className = 'border-top mt-1 pt-1';
            addMetaRow(group, label(name), '');
            Object.entries(value).forEach(function (entry) {
                appendNestedRows(group, entry[0], entry[1]);
            });
            parent.appendChild(group);
            return;
        }
        if (Array.isArray(value)) {
            value.forEach(function (item, index) {
                appendNestedRows(parent, name + ' ' + (index + 1), item);
            });
            return;
        }
        addMetaRow(parent, label(name), value);
    }

    function showHealthFields(data) {
        content.replaceChildren();

        var heading = document.createElement('div');
        heading.className = 'd-flex align-items-center justify-content-between gap-3 mb-2';
        var overall = document.createElement('div');
        overall.className = 'd-flex align-items-center gap-2';
        var title = document.createElement('strong');
        title.textContent = 'Overall status';
        overall.appendChild(title);
        overall.appendChild(statusBadge(data.status));
        heading.appendChild(overall);

        var refreshButton = document.createElement('button');
        refreshButton.type = 'button';
        refreshButton.className = 'btn btn-sm btn-outline-secondary';
        refreshButton.textContent = 'Refresh';
        refreshButton.addEventListener('click', function () {
            loadHealth(true);
        });
        heading.appendChild(refreshButton);
        content.appendChild(heading);

        var message = document.createElement('p');
        message.className = 'small text-muted mb-2';
        var attentionChecks = Object.entries(data.checks || {})
            .filter(function (entry) {
                return ['degraded', 'unhealthy'].indexOf((entry[1] || {}).status) !== -1;
            })
            .map(function (entry) { return label(entry[0]); });
        message.textContent = attentionChecks.length
            ? 'Needs attention: ' + attentionChecks.join(', ')
            : 'All checks are healthy.';
        content.appendChild(message);

        var meta = document.createElement('div');
        meta.className = 'border-bottom pb-2 mb-2';
        addMetaRow(meta, 'Timestamp', data.timestamp);
        if (data.checked_at !== data.timestamp) {
            addMetaRow(meta, 'Checked at', data.checked_at);
        }
        addMetaRow(meta, 'Version', data.version);
        addMetaRow(meta, 'Uptime', formatUptime(data.uptime_seconds));
        addMetaRow(meta, 'Duration', data.duration_ms == null ? '' : data.duration_ms + ' ms');
        if (data.cached === true) {
            var cachedBadge = document.createElement('span');
            cachedBadge.className = 'badge bg-secondary';
            cachedBadge.textContent = 'Cached';
            meta.appendChild(cachedBadge);
        }
        content.appendChild(meta);

        Object.entries(data.checks || {}).forEach(function (entry) {
            var name = entry[0];
            var check = entry[1] || {};
            var details = document.createElement('details');
            details.className = 'border-bottom py-2';

            var summary = document.createElement('summary');
            summary.className = 'd-flex align-items-center justify-content-between gap-2';
            var left = document.createElement('span');
            left.className = 'd-flex align-items-center gap-2';
            var dot = document.createElement('span');
            dot.className = statusClass(check.status);
            dot.textContent = '●';
            left.appendChild(dot);
            var checkName = document.createElement('span');
            checkName.textContent = label(name);
            left.appendChild(checkName);
            var tags = document.createElement('span');
            tags.className = 'd-flex align-items-center gap-1';
            var tier = document.createElement('span');
            tier.className = 'badge bg-secondary';
            tier.textContent = label(check.tier || 'optional');
            tags.appendChild(tier);
            tags.appendChild(statusBadge(check.status));
            summary.appendChild(left);
            summary.appendChild(tags);
            details.appendChild(summary);

            var detailBody = document.createElement('div');
            detailBody.className = 'small text-muted ps-3 pt-2';
            addMetaRow(detailBody, 'Summary', check.summary);
            addMetaRow(detailBody, 'Latency (ms)', check.latency_ms);
            Object.entries(check).forEach(function (field) {
                if (['status', 'tier', 'summary', 'latency_ms'].indexOf(field[0]) !== -1) return;
                appendNestedRows(detailBody, field[0], field[1]);
            });
            details.appendChild(detailBody);
            content.appendChild(details);
        });
    }

    function loadHealth(refresh) {
        showMessage('Loading health status…');
        modal.show();

        fetch('/api/config/health/detailed' + (refresh ? '?refresh=true' : ''))
            .then(function (response) {
                if (!response.ok) {
                    showMessage(response.status === 403
                        ? 'Health status is only visible to admins.'
                        : "Couldn't load health status.");
                    return null;
                }

                return response.json().then(function (data) {
                    if (!data || typeof data !== 'object' || Array.isArray(data)) {
                        showMessage("Couldn't load health status.");
                        return;
                    }
                    showHealthFields(data);
                });
            })
            .catch(function () {
                showMessage("Couldn't load health status.");
            });
    }

    button.addEventListener('click', function () {
        loadHealth(false);
    });
})();
