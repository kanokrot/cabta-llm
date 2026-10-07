(function () {
    'use strict';

    var BODY_IDS = { scoring: 'scoringSources', report: 'reportSources', sandbox: 'sandboxSources' };

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function request(url, options) {
        return fetch(url, options || {}).then(function (response) {
            return response.json().catch(function () { return {}; }).then(function (body) {
                if (!response.ok) throw new Error(body.detail || body.error || ('HTTP ' + response.status));
                return body;
            });
        });
    }

    function showError(message) {
        var box = document.getElementById('sourcesError');
        if (!box) return;
        box.textContent = message;
        box.hidden = false;
    }

    function statusText(source) {
        return source.configured ? 'Configured' : 'Not set';
    }

    function buildRow(source) {
        var row = el('tr');
        var label = el('th');
        label.scope = 'row';
        label.appendChild(el('span', 'source-name', source.label));
        if (source.note) label.appendChild(el('span', 'source-note', source.note));
        row.appendChild(label);
        var status = el('td', source.configured ? 'text-success' : 'text-muted');
        status.appendChild(source.configured
            ? el('i', 'bi bi-check-circle-fill source-status-icon configured')
            : el('span', 'source-status-icon not-set'));
        status.appendChild(document.createTextNode(statusText(source)));
        row.appendChild(status);

        var inputCell = el('td');
        var input = el('input', 'form-control form-control-sm source-key-input');
        input.type = 'password';
        input.classList.add('font-monospace');
        input.autocomplete = 'new-password';
        input.maxLength = 4096;
        input.dataset.keyInput = source.id;
        input.placeholder = source.configured ? source.masked_preview : 'Enter API key';
        input.setAttribute('aria-label', source.label + ' API key');
        inputCell.appendChild(input);
        row.appendChild(inputCell);

        var actions = el('td', 'text-nowrap');
        var save = el('button', 'btn btn-sm btn-outline-primary me-1');
        save.type = 'button';
        save.title = 'Save ' + source.label + ' key';
        save.setAttribute('aria-label', save.title);
        save.appendChild(el('i', 'bi bi-check-lg'));
        save.addEventListener('click', function () { saveKey(source, input); });
        actions.appendChild(save);
        if (source.configured) {
            var clear = el('button', 'btn btn-sm btn-outline-danger');
            clear.type = 'button';
            clear.title = 'Clear ' + source.label + ' key';
            clear.setAttribute('aria-label', clear.title);
            clear.appendChild(el('i', 'bi bi-trash'));
            clear.addEventListener('click', function () { clearKey(source); });
            actions.appendChild(clear);
        }
        row.appendChild(actions);
        return row;
    }

    function render(sources) {
        Object.keys(BODY_IDS).forEach(function (tier) {
            var body = document.getElementById(BODY_IDS[tier]);
            var heading = body.firstElementChild;
            body.replaceChildren(heading);
            sources.filter(function (source) { return source.tier === tier; }).forEach(function (source) { body.appendChild(buildRow(source)); });
        });
    }

    function load() {
        var box = document.getElementById('sourcesError');
        if (!box) return;
        box.hidden = true;
        request('/api/config/settings/sources').then(function (payload) { render(payload.sources || []); }).catch(function (error) { showError(error.message || 'Could not load source settings.'); });
    }

    function setStatus(message) {
        var node = document.getElementById('sourcesSaveStatus');
        if (node) node.textContent = message;
    }

    function saveKey(source, input) {
        var value = input.value.trim();
        if (!value) {
            setStatus('Enter a key before saving.');
            return;
        }
        var body = { api_keys: {} };
        body.api_keys[source.config_keys[0]] = value;
        setStatus('Saving…');
        request('/api/config/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(function () {
            setStatus('Saved. Restart to apply.');
            load();
        }).catch(function (error) { setStatus(''); showError(error.message || 'Could not save key.'); });
    }

    function clearKey(source) {
        setStatus('Clearing…');
        request('/api/config/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ clear_api_keys: [source.id] }) }).then(function () {
            setStatus('Cleared. Restart to apply.');
            load();
        }).catch(function (error) { setStatus(''); showError(error.message || 'Could not clear key.'); });
    }

    function init() { if (document.getElementById('sources-panel')) load(); }
    window.SettingsSources = { init: init, load: load };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
}());
