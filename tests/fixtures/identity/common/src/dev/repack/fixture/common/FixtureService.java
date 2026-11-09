package dev.repack.fixture.common;

import android.app.Service;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.os.IBinder;

public final class FixtureService extends Service {
    private String token;
    @Override public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("fixture", "Repack fixture", NotificationManager.IMPORTANCE_MIN));
        startForeground(1, new Notification.Builder(this, "fixture")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("Repack fixture component test").build());
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        token = intent.getStringExtra("token");
        SigningProbe.marker("service-onStart:" + token);
        return START_NOT_STICKY;
    }
    @Override public void onDestroy() {
        stopForeground(true);
        SigningProbe.marker("service-onDestroy:" + token);
        super.onDestroy();
    }
    @Override public IBinder onBind(Intent intent) { return null; }
}
