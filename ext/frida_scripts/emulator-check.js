setTimeout(function() {
    Java.perform(function() {
        send("[.] Debug check bypass");

        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            send('isDebuggerConnected Bypassed !');
            return false;
        }


    });
}, 0);