(function () {
    'use strict';

    var SOURCES = {
        virustotal: 'VirusTotal',
        abuseipdb: 'AbuseIPDB',
        otx: 'AlienVault OTX'
    };

    function byId(id) { return document.getElementById(id); }

    function showError(message) {
        var node = byId('userApiKeysError');
        if (!node) return;
        node.textContent = message || 'Request failed. Please try again.';
        node.style.display = '';
    }

    function clearError() {
        var node = byId('userApiKeysError');
        if (node) {
            node.textContent = '';
            node.style.display = 'none';
        }
    }

    async function refresh() {
        var status = byId('userApiKeysStatus');
        if (!status) return;
        try {
            var response = await fetch('/api/account/intel-keys', { credentials: 'include' });
            if (!response.ok) throw new Error('Could not load API key status.');
            var payload = await response.json();
            var keys = Array.isArray(payload.keys) ? payload.keys : [];
            status.textContent = keys.map(function (item) {
                var label = SOURCES[item.source];
                if (!label) return '';
                var detail = item.configured ? 'configured' : 'not configured';
                if (item.last_used_at) detail += ' · last used ' + item.last_used_at;
                return label + ': ' + detail;
            }).filter(Boolean).join('  |  ');
        } catch (error) {
            status.textContent = 'Key status is unavailable.';
            showError('Could not load API key status.');
        }
    }

    async function save() {
        clearError();
        var source = byId('userApiKeySource').value;
        var input = byId('userApiKeyValue');
        var apiKey = input.value;
        if (!Object.prototype.hasOwnProperty.call(SOURCES, source) || !apiKey.trim()) {
            showError('Choose a source and enter an API key.');
            return;
        }
        try {
            var response = await fetch('/api/account/intel-keys/' + encodeURIComponent(source), {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: apiKey })
            });
            if (!response.ok) throw new Error('Could not save API key.');
            input.value = '';
            await refresh();
        } catch (error) {
            showError(error.message || 'Could not save API key.');
        }
    }

    async function remove() {
        clearError();
        var source = byId('userApiKeySource').value;
        if (!Object.prototype.hasOwnProperty.call(SOURCES, source)) return;
        try {
            var response = await fetch('/api/account/intel-keys/' + encodeURIComponent(source), {
                method: 'DELETE', credentials: 'include'
            });
            if (!response.ok) throw new Error('Could not delete API key.');
            await refresh();
        } catch (error) {
            showError(error.message || 'Could not delete API key.');
        }
    }

    function init() {
        if (!byId('userApiKeySave')) return;
        byId('userApiKeySave').addEventListener('click', save);
        byId('userApiKeyDelete').addEventListener('click', remove);
        refresh();
    }

    window.AccountApiKeys = { init: init };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
