/*
 * This script combines, fixes & extends a long list of other scripts, most notably including:
 *
 * - https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/
 * - https://codeshare.frida.re/@avltree9798/universal-android-ssl-pinning-bypass/
 * - https://pastebin.com/TVJD63uM
 */

setTimeout(function () {
    Java.perform(function () {
        send("Unpinning Android app...");

        try{
            var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
            send('[+] squareup OkHTTP CertificatePinner found. Hooking bypass.');
            OkHttpClient.setCertificatePinner.implementation = function(certificatePinner){
                // do nothing
                send("--> OkHttpClient Bypassed [certificatePinner]");
                return this;
            };

            // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
            var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1){
                // do nothing
                send("--> OkHttpClient Bypassed [Certificate]");
                return;
            };
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){
                // do nothing
                send("--> OkHttpClient Bypassed [List Certificates]");
                return;
            };
        } catch (err) {
            send('[-] squareup OkHTTP CertificatePinner class not found. Skipping.');
        }

        try{
            var OkHostnameVerifier = Java.use("com.squareup.okhttp.internal.tls.OkHostnameVerifier");
            send('[+] squareup OkHTTP OkHostnameVerifier found. Hooking bypass.');
            OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str,cert) {
	            send('[+] Bypassing HostnameVerifier: ' + str);
	            return true;
	        };

	        OkHostnameVerifier.verifyHostName.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str,cert) {
	            send('[+] Bypassing HostnameVerifier: ' + str);
	            return true;
	        };

        } catch {
            send('[-] squareup OkHostnameVerifier class not found. Skipping.');
        }

        try{
            var CertificateChainCleaner = Java.use("com.squareup.okhttp.internal.tls.CertificateChainCleaner");
            send('[+] squareup OkHTTP CertificateChainCleaner found. Hooking bypass.');
            CertificateChainCleaner.verifySignature.overload('java.security.cert.X509Certificate', 'java.security.cert.X509Certificate').implementation = function (str,cert) {
	            send('[+] Bypassing pubkey validation');
	            return true;
	        };
        } catch {
            send('[-] squareup CertificateChainCleaner class not found. Skipping.');
        }

        try {

            // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
            var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1){
                // do nothing
                send("--> OkHttpClient Bypassed [Certificate]");
                return;
            };
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){
                // do nothing
                send("--> OkHttpClient Bypassed [List Certificates]");
                return;
            };
        } catch (err) {
            send('[-] squareup OkHTTP CertificatePinner class not found. Skipping.');
        }
        
        var okhttp3_CertificatePinner_class = null;
        try {
            okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');    
        } catch (err) {
            send('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
            okhttp3_CertificatePinner_class = null;
        }
        if(okhttp3_CertificatePinner_class != null) {
	        try{
	            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str,list) {
	                send('[+] Bypassing OkHTTPv3 1: ' + str);
	                return true;
	            };
	            send('[+] Loaded OkHTTPv3 hook 1');
	        } catch(err) {
	        	send('[-] Skipping OkHTTPv3 hook 1');
	        }
	        try{
	            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str,cert) {
	                send('[+] Bypassing OkHTTPv3 2: ' + str);
	                return true;
	            };
	            send('[+] Loaded OkHTTPv3 hook 2');
	        } catch(err) {
	        	send('[-] Skipping OkHTTPv3 hook 2');
	        }
	        try {
	            okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str,cert_array) {
	                send('[+] Bypassing OkHTTPv3 3: ' + str);
	                return true;
	            };
	            send('[+] Loaded OkHTTPv3 hook 3');
	        } catch(err) {
	        	send('[-] Skipping OkHTTPv3 hook 3');
	        }
	        try {
	            okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str,obj) {
		            send('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
		        };
		        send('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
		    } catch(err) {
	        	send('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
	        }
		}

        // HttpsURLConnection
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                send('  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)');
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            send('[+] HttpsURLConnection (setDefaultHostnameVerifier)');
        } catch (err) {
            send('[ ] HttpsURLConnection (setDefaultHostnameVerifier)');
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
                send('  --> Bypassing HttpsURLConnection (setSSLSocketFactory)');
                return; // Do nothing, i.e. don't change the SSL socket factory
            };
            send('[+] HttpsURLConnection (setSSLSocketFactory)');
        } catch (err) {
            send('[ ] HttpsURLConnection (setSSLSocketFactory)');
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                send('  --> Bypassing HttpsURLConnection (setHostnameVerifier)');
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            send('[+] HttpsURLConnection (setHostnameVerifier)');
        } catch (err) {
            send('[ ] HttpsURLConnection (setHostnameVerifier)');
        }

        // SSLContext
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });

            // Prepare the TrustManager array to pass to SSLContext.init()
            const TrustManagers = [TrustManager.$new()];

            // Get a handle on the init() on the SSLContext class
            const SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            );

            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                send('  --> Bypassing Trustmanager (Android < 7) request');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            send('[+] SSLContext');
        } catch (err) {
            send('[ ] SSLContext');
        }

        // TrustManagerImpl (Android > 7)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

            // This step is notably what defeats the most common case: network security config
            TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                send('  --> Bypassing TrustManagerImpl checkTrusted ');
                return array_list.$new();
            }

            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                send('  --> Bypassing TrustManagerImpl verifyChain: ' + host);
                return untrustedChain;
            };
            send('[+] TrustManagerImpl');
        } catch (err) {
            send('[ ] TrustManagerImpl');
        }

        // OkHTTPv3 (quadruple bypass)
        try {
            // Bypass OkHTTPv3 {1}
            const okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                send('  --> Bypassing OkHTTPv3 (list): ' + a);
                return;
            };
            send('[+] OkHTTPv3 (list)');
        } catch (err) {
            send('[ ] OkHTTPv3 (list)');
        }
        try {
            // Bypass OkHTTPv3 {2}
            // This method of CertificatePinner.check could be found in some old Android app
            const okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                send('  --> Bypassing OkHTTPv3 (cert): ' + a);
                return;
            };
            send('[+] OkHTTPv3 (cert)');
        } catch (err) {
            send('[ ] OkHTTPv3 (cert)');
        }
        try {
            // Bypass OkHTTPv3 {3}
            const okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
                send('  --> Bypassing OkHTTPv3 (cert array): ' + a);
                return;
            };
            send('[+] OkHTTPv3 (cert array)');
        } catch (err) {
            send('[ ] OkHTTPv3 (cert array)');
        }
        try {
            // Bypass OkHTTPv3 {4}
            const okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
                send('  --> Bypassing OkHTTPv3 ($okhttp): ' + a);
                return;
            };
            send('[+] OkHTTPv3 ($okhttp)');
        } catch (err) {
            send('[ ] OkHTTPv3 ($okhttp)');
        }

        // Trustkit (triple bypass)
        try {
            // Bypass Trustkit {1}
            const trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                send('  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): ' + a);
                return true;
            };
            send('[+] Trustkit OkHostnameVerifier(SSLSession)');
        } catch (err) {
            send('[ ] Trustkit OkHostnameVerifier(SSLSession)');
        }
        try {
            // Bypass Trustkit {2}
            const trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                send('  --> Bypassing Trustkit OkHostnameVerifier(cert): ' + a);
                return true;
            };
            send('[+] Trustkit OkHostnameVerifier(cert)');
        } catch (err) {
            send('[ ] Trustkit OkHostnameVerifier(cert)');
        }
        try {
            // Bypass Trustkit {3}
            const trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
                send('  --> Bypassing Trustkit PinningTrustManager');
            };
            send('[+] Trustkit PinningTrustManager');
        } catch (err) {
            send('[ ] Trustkit PinningTrustManager');
        }

        // Appcelerator Titanium
        try {
            const appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
                send('  --> Bypassing Appcelerator PinningTrustManager');
            };
            send('[+] Appcelerator PinningTrustManager');
        } catch (err) {
            send('[ ] Appcelerator PinningTrustManager');
        }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                send('  --> Bypassing OpenSSLSocketImpl Conscrypt');
            };
            send('[+] OpenSSLSocketImpl Conscrypt');
        } catch (err) {
            send('[ ] OpenSSLSocketImpl Conscrypt');
        }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
                send('  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
            };
            send('[+] OpenSSLEngineSocketImpl Conscrypt');
        } catch (err) {
            send('[ ] OpenSSLEngineSocketImpl Conscrypt');
        }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                send('  --> Bypassing OpenSSLSocketImpl Apache Harmony');
            };
            send('[+] OpenSSLSocketImpl Apache Harmony');
        } catch (err) {
            send('[ ] OpenSSLSocketImpl Apache Harmony');
        }

        // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
        try {
            const phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
            phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                send('  --> Bypassing PhoneGap sslCertificateChecker: ' + a);
                return true;
            };
            send('[+] PhoneGap sslCertificateChecker');
        } catch (err) {
            send('[ ] PhoneGap sslCertificateChecker');
        }

        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            // Bypass IBM MobileFirst {1}
            const WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                send('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): ' + cert);
                return;
            };
            send('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
        } catch (err) {
            send('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
        }
        try {
            // Bypass IBM MobileFirst {2}
            const WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                send('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): ' + cert);
                return;
            };
            send('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
        } catch (err) {
            send('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
        }

        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
        try {
            // Bypass IBM WorkLight {1}
            const worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
                send('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): ' + a);
                return;
            };
            send('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
        } catch (err) {
            send('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
        }
        try {
            // Bypass IBM WorkLight {2}
            const worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                send('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): ' + a);
                return;
            };
            send('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
        } catch (err) {
            send('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
        }
        try {
            // Bypass IBM WorkLight {3}
            const worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
                send('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): ' + a);
                return;
            };
            send('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
        } catch (err) {
            send('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
        }
        try {
            // Bypass IBM WorkLight {4}
            const worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                send('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): ' + a);
                return true;
            };
            send('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
        } catch (err) {
            send('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
        }

        // Conscrypt CertPinManager
        try {
            const conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
            conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                send('  --> Bypassing Conscrypt CertPinManager: ' + a);
                return true;
            };
            send('[+] Conscrypt CertPinManager');
        } catch (err) {
            send('[ ] Conscrypt CertPinManager');
        }

        // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
        try {
            const cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                send('  --> Bypassing CWAC-Netsecurity CertPinManager: ' + a);
                return true;
            };
            send('[+] CWAC-Netsecurity CertPinManager');
        } catch (err) {
            send('[ ] CWAC-Netsecurity CertPinManager');
        }

        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            const androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                send('  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
                return true;
            };
            send('[+] Worklight Androidgap WLCertificatePinningPlugin');
        } catch (err) {
            send('[ ] Worklight Androidgap WLCertificatePinningPlugin');
        }

        // Netty FingerprintTrustManagerFactory
        try {
            const netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                send('  --> Bypassing Netty FingerprintTrustManagerFactory');
            };
            send('[+] Netty FingerprintTrustManagerFactory');
        } catch (err) {
            send('[ ] Netty FingerprintTrustManagerFactory');
        }

        // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
        try {
            // Bypass Squareup CertificatePinner {1}
            const Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                send('  --> Bypassing Squareup CertificatePinner (cert): ' + a);
                return;
            };
            send('[+] Squareup CertificatePinner (cert)');
        } catch (err) {
            send('[ ] Squareup CertificatePinner (cert)');
        }
        try {
            // Bypass Squareup CertificatePinner {2}
            const Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                send('  --> Bypassing Squareup CertificatePinner (list): ' + a);
                return;
            };
            send('[+] Squareup CertificatePinner (list)');
        } catch (err) {
            send('[ ] Squareup CertificatePinner (list)');
        }

        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
        try {
            // Bypass Squareup OkHostnameVerifier {1}
            const Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                send('  --> Bypassing Squareup OkHostnameVerifier (cert): ' + a);
                return true;
            };
            send('[+] Squareup OkHostnameVerifier (cert)');
        } catch (err) {
            send('[ ] Squareup OkHostnameVerifier (cert)');
        }
        try {
            // Bypass Squareup OkHostnameVerifier {2}
            const Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                send('  --> Bypassing Squareup OkHostnameVerifier (SSLSession): ' + a);
                return true;
            };
            send('[+] Squareup OkHostnameVerifier (SSLSession)');
        } catch (err) {
            send('[ ] Squareup OkHostnameVerifier (SSLSession)');
        }

        // Android WebViewClient (double bypass)
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            const AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                send('  --> Bypassing Android WebViewClient (SslErrorHandler)');
            };
            send('[+] Android WebViewClient (SslErrorHandler)');
        } catch (err) {
            send('[ ] Android WebViewClient (SslErrorHandler)');
        }
        try {
            // Bypass WebViewClient {2}
            const AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
                send('  --> Bypassing Android WebViewClient (WebResourceError)');
            };
            send('[+] Android WebViewClient (WebResourceError)');
        } catch (err) {
            send('[ ] Android WebViewClient (WebResourceError)');
        }

        // Apache Cordova WebViewClient
        try {
            const CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
            CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                send('  --> Bypassing Apache Cordova WebViewClient');
                obj3.proceed();
            };
        } catch (err) {
            send('[ ] Apache Cordova WebViewClient');
        }

        // Boye AbstractVerifier
        try {
            const boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            boye_AbstractVerifier.verify.implementation = function (host, ssl) {
                send('  --> Bypassing Boye AbstractVerifier: ' + host);
            };
        } catch (err) {
            send('[ ] Boye AbstractVerifier');
        }
    });

    send("Unpinning setup completed");

}, 0);