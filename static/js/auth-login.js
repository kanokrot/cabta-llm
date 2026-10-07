(function () {
    'use strict';

    function initializePasswordReveal() {
        var button = document.getElementById('auth-login-reveal');
        var password = document.getElementById('login-password');
        if (!button || !password) return;

        var icon = button.querySelector('i');

        function setVisible(visible) {
            password.type = visible ? 'text' : 'password';
            button.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
            button.setAttribute('aria-pressed', visible ? 'true' : 'false');
            if (icon) {
                icon.classList.toggle('bi-eye', !visible);
                icon.classList.toggle('bi-eye-slash', visible);
            }
        }

        setVisible(false);
        button.addEventListener('click', function () {
            setVisible(password.type === 'password');
            password.focus();
            password.setSelectionRange(2147483647, 2147483647);
        });

        var form = document.getElementById('login-form');
        if (form) {
            form.addEventListener('submit', function () {
                setVisible(false);
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializePasswordReveal);
    } else {
        initializePasswordReveal();
    }
}());
