(function () {
    'use strict';

    var SOURCES = [
        { id: 'virustotal', label: 'VirusTotal' },
        { id: 'abuseipdb', label: 'AbuseIPDB' },
        { id: 'otx', label: 'AlienVault OTX' }
    ];

    function byId(id) { return document.getElementById(id); }

    function showError() {
        var node = byId('userApiKeysError');
        if (!node) return;
        node.textContent = 'Could not update personal API keys. Please try again.';
        node.style.display = '';
    }

    function clearError() {
        var node = byId('userApiKeysError');
        if (node) {
            node.textContent = '';
            node.style.display = 'none';
        }
    }

    function make(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    async function request(url, options) {
        var response = await fetch(url, options || { credentials: 'include' });
        if (!response.ok) throw new Error('request failed');
        return response.status === 204 ? null : response.json();
    }

    function renderRow(source, metadata) {
        var row = make('div', 'row g-3 align-items-center border-bottom pb-3');
        var identity = make('div', 'col-md-3');
        identity.appendChild(make('div', 'fw-semibold', source.label));
        row.appendChild(identity);

        var status = make('div', 'col-md-3');
        status.appendChild(make('div', metadata.configured ? 'text-success small' : 'text-muted small', metadata.configured ? 'Configured' : 'Not set'));
        if (metadata.configured) {
            status.appendChild(make('span', 'font-monospace small', metadata.masked_suffix || '••••'));
        }
        row.appendChild(status);

        var controls = make('div', 'col-md-6 d-flex flex-column flex-md-row gap-2 align-items-stretch align-items-md-center');
        if (metadata.configured) {
            var remove = make('button', 'btn btn-outline-danger btn-sm', 'Remove');
            remove.type = 'button';
            remove.addEventListener('click', function () { removeKey(source); });
            controls.appendChild(remove);
        } else {
            var input = make('input', 'form-control form-control-sm flex-grow-1');
            input.type = 'password';
            input.autocomplete = 'new-password';
            input.maxLength = 4096;
            input.placeholder = 'Enter API key';
            input.setAttribute('aria-label', source.label + ' API key');
            var save = make('button', 'btn btn-accent btn-sm', 'Save');
            save.type = 'button';
            save.addEventListener('click', function () { saveKey(source, input); });
            controls.appendChild(input);
            controls.appendChild(save);
        }
        row.appendChild(controls);
        return row;
    }

    function render(keys) {
        var container = byId('userApiKeysRows');
        var bySource = {};
        (Array.isArray(keys) ? keys : []).forEach(function (item) { bySource[item.source] = item; });
        container.replaceChildren();
        SOURCES.forEach(function (source) {
            var metadata = bySource[source.id] || { configured: false };
            container.appendChild(renderRow(source, metadata));
        });
    }

    async function refresh() {
        clearError();
        var container = byId('userApiKeysRows');
        if (!container) return;
        try {
            var payload = await request('/api/account/intel-keys', { credentials: 'include' });
            var disabled = byId('userApiKeysDisabled');
            if (payload && payload.enabled === false) {
                disabled.style.display = '';
                container.style.display = 'none';
                return;
            }
            disabled.style.display = 'none';
            container.style.display = '';
            render(payload && payload.keys);
        } catch (error) {
            container.replaceChildren();
            showError();
        }
    }

    async function saveKey(source, input) {
        clearError();
        var apiKey = input.value;
        if (!apiKey.trim()) return;
        try {
            await request('/api/account/intel-keys/' + encodeURIComponent(source.id), {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: apiKey })
            });
            input.value = '';
            await refresh();
        } catch (error) {
            showError();
        }
    }

    async function removeKey(source) {
        clearError();
        try {
            await request('/api/account/intel-keys/' + encodeURIComponent(source.id), {
                method: 'DELETE', credentials: 'include'
            });
            await refresh();
        } catch (error) {
            showError();
        }
    }

    function init() { if (byId('userApiKeysRows')) refresh(); }
    window.AccountApiKeys = { init: init };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
}());
