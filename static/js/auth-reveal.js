(function () {
    'use strict';

    function setHidden(button, input) {
        input.type = 'password';
        button.setAttribute('aria-label', 'Show password');
        button.setAttribute('aria-pressed', 'false');
        var icon = button.querySelector('i');
        if (icon) {
            icon.classList.remove('bi-eye-slash');
            icon.classList.add('bi-eye');
        }
    }

    function initializePasswordReveal() {
        var buttons = document.querySelectorAll('button.auth-console-reveal[aria-controls]');
        var forms = [];

        buttons.forEach(function (button) {
            var input = document.getElementById(button.getAttribute('aria-controls'));
            if (!input) return;

            setHidden(button, input);
            button.addEventListener('click', function () {
                var visible = input.type === 'password';
                input.type = visible ? 'text' : 'password';
                button.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
                button.setAttribute('aria-pressed', visible ? 'true' : 'false');
                var icon = button.querySelector('i');
                if (icon) {
                    icon.classList.toggle('bi-eye', !visible);
                    icon.classList.toggle('bi-eye-slash', visible);
                }
                input.focus();
                input.setSelectionRange(2147483647, 2147483647);
            });

            var form = button.closest('form');
            if (!form || forms.indexOf(form) !== -1) return;
            forms.push(form);
            form.addEventListener('submit', function () {
                form.querySelectorAll('button.auth-console-reveal[aria-controls]').forEach(function (formButton) {
                    var formInput = document.getElementById(formButton.getAttribute('aria-controls'));
                    if (formInput) setHidden(formButton, formInput);
                });
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializePasswordReveal);
    } else {
        initializePasswordReveal();
    }
}());
