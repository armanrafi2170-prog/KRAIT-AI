(function() {
    'use strict';

    var socket = null;

    function initSocket() {
        try {
            socket = io({
                transports: ['websocket', 'polling'],
                reconnection: true,
                reconnectionAttempts: 10,
                reconnectionDelay: 1000
            });

            window._socket = socket;

            socket.on('connect', function() {
                console.log('[KRAIT] WebSocket connected:', socket.id);
            });

            socket.on('disconnect', function() {
                console.log('[KRAIT] WebSocket disconnected');
            });

            socket.on('connect_error', function(err) {
                console.warn('[KRAIT] Connection error:', err.message);
            });

            socket.on('scan_update', function(data) {
                console.log('[KRAIT] Scan update:', data);
                if (typeof window._onScanUpdate === 'function') {
                    window._onScanUpdate(data);
                }
            });

            socket.on('scan_state', function(data) {
                console.log('[KRAIT] Scan state:', data);
            });

        } catch(e) {
            console.warn('[KRAIT] WebSocket init failed:', e);
        }
    }

    function showAlert(message, type) {
        type = type || 'info';
        var alert = document.createElement('div');
        alert.className = 'alert alert-' + type;
        alert.textContent = message;

        var main = document.querySelector('.main-content');
        if (main) {
            main.insertBefore(alert, main.firstChild);
            setTimeout(function() {
                if (alert.parentNode) alert.parentNode.removeChild(alert);
            }, 5000);
        }
    }

    window.showAlert = showAlert;

    function formatTimestamp(isoString) {
        if (!isoString) return '—';
        try {
            var d = new Date(isoString);
            return d.toLocaleString();
        } catch(e) {
            return isoString;
        }
    }

    function initPage() {
        var loginForm = document.querySelector('.login-form');
        if (!loginForm) {
            initSocket();
        }

        var scanRows = document.querySelectorAll('[data-scan-id]');
        scanRows.forEach(function(row) {
            var scanId = parseInt(row.dataset.scanId);
            if (scanId && socket) {
                var status = row.dataset.status;
                if (status === 'running' || status === 'queued') {
                    socket.emit('join_scan', { scan_id: scanId });
                }
            }
        });

        document.querySelectorAll('.speed-option').forEach(function(opt) {
            opt.addEventListener('click', function() {
                document.querySelectorAll('.speed-option').forEach(function(o) {
                    o.classList.remove('active');
                });
                opt.classList.add('active');
                var radio = opt.querySelector('input[type="radio"]');
                if (radio) radio.checked = true;
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPage);
    } else {
        initPage();
    }

    window.KRAIT = {
        version: '1.0.0',
        socket: function() { return socket; }
    };

})();
