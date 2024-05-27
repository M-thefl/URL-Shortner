document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('shorten-form');
    const urlInput = document.getElementById('url-input');
    const messageContainer = document.getElementById('message-container');

    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const url = urlInput.value.trim();
        if (url === '') {
            showMessage('error', 'Please enter a URL.');
            return;
        }
        shortenURL(url);
    });

    function shortenURL(url) {
        // Placeholder for URL shortening process
        showMessage('success', 'URL shortened successfully!');
    }

    function showMessage(type, text) {
        const message = document.createElement('div');
        message.className = `alert ${type}`;
        message.textContent = text;
        messageContainer.appendChild(message);
        setTimeout(() => message.remove(), 5000); // Remove message after 5 seconds
    }
});
