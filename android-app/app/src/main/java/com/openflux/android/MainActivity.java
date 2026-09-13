package com.openflux.android;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.Locale;

import mobile.Mobile;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 1001;
    private static final String CONFIG_PREFS = "openflux_config";

    private Spinner transportSpinner;
    private EditText yandexUrl;
    private EditText maxToken;
    private EditText maxUid;
    private TextView status;
    private Button connect;
    private Button disconnect;
    private String pendingConfig;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable statusPoll = new Runnable() {
        @Override public void run() {
            refreshStatus();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Mobile.touch();
        buildUi();
        loadConfig();
        handler.post(statusPoll);
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(18);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("OpenFlux Android");
        title.setTextSize(26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("SOCKS5 + tun2socks VPN. DNS идёт через OpenFlux. Остальной UDP/QUIC пока не поддерживается и должен откатываться на TCP.");
        subtitle.setTextSize(14);
        subtitle.setPadding(0, dp(6), 0, dp(18));
        root.addView(subtitle);

        addLabel(root, "Транспорт");
        transportSpinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item,
                new String[]{"Yandex Docs", "MAX / OneMe (экспериментально)"});
        transportSpinner.setAdapter(adapter);
        root.addView(transportSpinner, fullWidth());

        addLabel(root, "Публичная ссылка Yandex Docs");
        yandexUrl = edit("https://...");
        yandexUrl.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        root.addView(yandexUrl, fullWidth());

        addLabel(root, "MAX token");
        maxToken = edit("token");
        maxToken.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        root.addView(maxToken, fullWidth());

        addLabel(root, "MAX UID");
        maxUid = edit("numeric uid");
        maxUid.setInputType(InputType.TYPE_CLASS_NUMBER);
        root.addView(maxUid, fullWidth());

        transportSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateTransportFields();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        connect = new Button(this);
        connect.setText("Подключить");
        connect.setOnClickListener(v -> requestConnect());
        root.addView(connect, fullWidthWithTop(18));

        disconnect = new Button(this);
        disconnect.setText("Отключить");
        disconnect.setOnClickListener(v -> requestDisconnect());
        root.addView(disconnect, fullWidthWithTop(8));

        addLabel(root, "Статус");
        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setTextSize(14);
        status.setPadding(dp(12), dp(12), dp(12), dp(12));
        root.addView(status, fullWidth());

        setContentView(scroll);
    }

    private void updateTransportFields() {
        boolean yandex = transportSpinner.getSelectedItemPosition() == 0;
        yandexUrl.setVisibility(yandex ? View.VISIBLE : View.GONE);
        maxToken.setVisibility(yandex ? View.GONE : View.VISIBLE);
        maxUid.setVisibility(yandex ? View.GONE : View.VISIBLE);
    }

    private void requestConnect() {
        try {
            boolean useYandex = transportSpinner.getSelectedItemPosition() == 0;
            String transport = useYandex ? "yandex" : "oneme";
            String yUrl = yandexUrl.getText().toString().trim();
            String token = maxToken.getText().toString().trim();
            String uid = maxUid.getText().toString().trim();

            if (useYandex && yUrl.isEmpty()) {
                toast("Укажи публичную ссылку Yandex Docs");
                return;
            }
            if (!useYandex && (token.isEmpty() || uid.isEmpty())) {
                toast("Для MAX нужны token и UID");
                return;
            }

            JSONObject cfg = new JSONObject();
            cfg.put("transport", transport);
            cfg.put("yandexUrl", yUrl);
            cfg.put("maxToken", token);
            cfg.put("maxUid", uid);
            cfg.put("socksAddress", "127.0.0.1:1080");
            cfg.put("debug", false);
            pendingConfig = cfg.toString();
            saveConfig();

            Intent permission = VpnService.prepare(this);
            if (permission != null) {
                startActivityForResult(permission, VPN_REQUEST);
            } else {
                startVpnService();
            }
        } catch (Exception e) {
            toast(e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                startVpnService();
            } else {
                toast("Android не выдал разрешение VPN");
            }
        }
    }

    private void startVpnService() {
        if (pendingConfig == null) pendingConfig = buildSavedConfig();
        Intent intent = new Intent(this, OpenFluxVpnService.class);
        intent.setAction(OpenFluxVpnService.ACTION_START);
        intent.putExtra(OpenFluxVpnService.EXTRA_CONFIG, pendingConfig);
        startForegroundService(intent);
    }

    private void requestDisconnect() {
        Intent intent = new Intent(this, OpenFluxVpnService.class);
        intent.setAction(OpenFluxVpnService.ACTION_STOP);
        startService(intent);
    }

    private void refreshStatus() {
        SharedPreferences runtime = getSharedPreferences(OpenFluxVpnService.RUNTIME_PREFS, MODE_PRIVATE);
        String state = runtime.getString("state", "STOPPED");
        String error = runtime.getString("error", "");
        boolean active = "STARTING".equals(state) || "RUNNING".equals(state);
        connect.setEnabled(!active);
        disconnect.setEnabled(active);

        StringBuilder out = new StringBuilder();
        out.append("State: ").append(state);
        if (!error.isEmpty()) out.append("\nError: ").append(error);

        if (active) {
            out.append("\nMode: ").append(runtime.getString("mode", "SOCKS5 + tun2socks"));
            out.append("\ntun2socks: ").append(runtime.getBoolean("tun2socksAlive", false) ? "alive" : "not ready");
            String t2sLog = runtime.getString("tun2socksLog", "");
            if (!t2sLog.isEmpty()) out.append("\ntun2socks log: ").append(t2sLog);
            try {
                JSONObject s = new JSONObject(Mobile.statusJSON());
                out.append("\nTransport: ").append(s.optString("transport", "-"));
                out.append("\nConnected: ").append(s.optBoolean("connected", false));
                out.append("\nUptime: ").append(s.optLong("uptimeSeconds", 0)).append(" s");
                out.append("\nRX: ").append(formatBytes(s.optLong("bytesReceived", 0)));
                out.append("  TX: ").append(formatBytes(s.optLong("bytesSent", 0)));
                out.append("\nPackets RX/TX: ")
                        .append(s.optLong("packetsReceived", 0)).append(" / ")
                        .append(s.optLong("packetsSent", 0));
                out.append("\nDNS Q/A/F: ")
                        .append(runtime.getLong("dnsQueries", 0)).append(" / ")
                        .append(runtime.getLong("dnsAnswers", 0)).append(" / ")
                        .append(runtime.getLong("dnsFailures", 0));
                String dnsLast = runtime.getString("dnsLastFailure", "");
                if (!dnsLast.isEmpty()) out.append("\nDNS last: ").append(dnsLast);
                out.append("\nReconnects: ").append(s.optLong("reconnects", 0));
                String last = s.optString("lastError", "");
                if (!last.isEmpty()) out.append("\nCore: ").append(last);
            } catch (Throwable t) {
                out.append("\nCore status unavailable: ").append(t.getMessage());
            }
        }
        status.setText(out.toString());
    }

    private void saveConfig() {
        getSharedPreferences(CONFIG_PREFS, MODE_PRIVATE).edit()
                .putInt("transport", transportSpinner.getSelectedItemPosition())
                .putString("yandex", yandexUrl.getText().toString())
                .putString("maxToken", maxToken.getText().toString())
                .putString("maxUid", maxUid.getText().toString())
                .apply();
    }

    private void loadConfig() {
        SharedPreferences p = getSharedPreferences(CONFIG_PREFS, MODE_PRIVATE);
        transportSpinner.setSelection(p.getInt("transport", 0));
        yandexUrl.setText(p.getString("yandex", ""));
        maxToken.setText(p.getString("maxToken", ""));
        maxUid.setText(p.getString("maxUid", ""));
        updateTransportFields();
    }

    private String buildSavedConfig() {
        try {
            boolean useYandex = transportSpinner.getSelectedItemPosition() == 0;
            JSONObject cfg = new JSONObject();
            cfg.put("transport", useYandex ? "yandex" : "oneme");
            cfg.put("yandexUrl", yandexUrl.getText().toString().trim());
            cfg.put("maxToken", maxToken.getText().toString().trim());
            cfg.put("maxUid", maxUid.getText().toString().trim());
            cfg.put("socksAddress", "127.0.0.1:1080");
            cfg.put("debug", false);
            return cfg.toString();
        } catch (Exception e) {
            return "{}";
        }
    }

    private EditText edit(String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        return e;
    }

    private void addLabel(LinearLayout root, String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        label.setPadding(0, dp(14), 0, dp(4));
        root.addView(label);
    }

    private LinearLayout.LayoutParams fullWidth() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams fullWidthWithTop(int topDp) {
        LinearLayout.LayoutParams p = fullWidth();
        p.topMargin = dp(topDp);
        return p;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void toast(String text) {
        Toast.makeText(this, text == null ? "Ошибка" : text, Toast.LENGTH_LONG).show();
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb);
        return String.format(Locale.US, "%.1f MB", kb / 1024.0);
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(statusPoll);
        super.onDestroy();
    }
}
