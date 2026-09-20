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

    function showHealthFields(data) {
        content.replaceChildren();

        Object.entries(data).forEach(function (entry) {
            var key = entry[0];
            var value = entry[1];
            var row = document.createElement('div');
            row.className = 'd-flex justify-content-between gap-3 py-2 border-bottom';
            row.style.borderColor = 'var(--border-color)';

            var label = document.createElement('span');
            label.className = 'text-muted';
            label.textContent = key.replace(/_/g, ' ').replace(/^\w/, function (letter) {
                return letter.toUpperCase();
            });

            var fieldValue = document.createElement('span');
            fieldValue.className = 'text-end';
            fieldValue.textContent = value == null ? '' : String(value);

            row.appendChild(label);
            row.appendChild(fieldValue);
            content.appendChild(row);
        });
    }

    button.addEventListener('click', function () {
        showMessage('Loading health status…');
        modal.show();

        fetch('/api/config/health')
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
    });
})();
