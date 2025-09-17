package com.solura.app;

import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    @Override
    public void onStart() {
        super.onStart();
        // Forza la WebView ad aprire i link dentro l’app se il dominio è solura.uk
        this.bridge.getWebView().setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.contains("solura.uk")) {
                    return false; // Apri nella WebView
                }
                return true; // Altri link aprili fuori (Chrome o browser di sistema)
            }
        });
    }
}
