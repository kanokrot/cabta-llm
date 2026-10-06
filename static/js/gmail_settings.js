(function () {
    'use strict';

    function loadStatus() {
        fetch('/api/settings/gmail/status')
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(function (data) {
                var linked = data.linked === true;
                document.getElementById('gmailStatusLabel').textContent = data.revoked
                    ? 'Revoked'
                    : (linked ? 'Connected' : 'Not connected');
                document.getElementById('gmailAccount').textContent = linked
                    ? (data.google_email || 'Connected account')
                    : 'Not connected';
                document.getElementById('gmailScopes').textContent = linked
                    && data.granted_scopes && data.granted_scopes.length
                    ? data.granted_scopes.join(', ')
                    : '—';
                document.getElementById('gmailLastRefresh').textContent = data.last_refresh_at || '—';
                document.getElementById('gmailConnect').style.display = linked ? 'none' : '';
                document.getElementById('gmailDisconnect').style.display = linked ? '' : 'none';
            })
            .catch(function (error) {
                var message = document.getElementById('gmailError');
                message.textContent = 'Unable to load Gmail status: ' + error.message;
                message.style.display = '';
                document.getElementById('gmailStatusLabel').textContent = 'Unavailable';
            });
    }

    function connectGmail() {
        window.location.href = '/api/settings/gmail/connect';
    }

    function disconnectGmail() {
        fetch('/api/settings/gmail', { method: 'DELETE' })
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(loadStatus)
            .catch(function (error) {
                var message = document.getElementById('gmailError');
                message.textContent = 'Disconnect failed: ' + error.message;
                message.style.display = '';
            });
    }

    function init() {
        document.getElementById('gmailConnect').addEventListener('click', connectGmail);
        document.getElementById('gmailDisconnect').addEventListener('click', disconnectGmail);
        loadStatus();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
