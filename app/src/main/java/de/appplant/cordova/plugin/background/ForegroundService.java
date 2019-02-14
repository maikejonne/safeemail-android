/*
    Copyright 2013-2017 appPlant GmbH

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
 */

package de.appplant.cordova.plugin.background;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.Color;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.SystemClock;
import android.support.annotation.RequiresApi;
import android.support.v4.app.NotificationCompat;

import com.blockchain.safeemail.MainActivity;
import com.blockchain.safeemail.R;

import org.json.JSONObject;

import java.lang.reflect.Method;

/**
 * Puts the service in a foreground state, where the system considers it to be
 * something the user is actively aware of and thus not a candidate for killing
 * when low on memory.
 */
public class ForegroundService extends Service {

    private AlarmManager alarmMgr;
    private PendingIntent alarmIntent;

    // Fixed ID for the 'foreground' notification
    public static final int NOTIFICATION_ID = -574543954;

    // Default title of the background notification
    private static final String NOTIFICATION_TITLE =
            "App is running in background";

    // Default text of the background notification
    private static final String NOTIFICATION_TEXT =
            "Doing heavy tasks.";

    // Default icon of the background notification
    private static final String NOTIFICATION_ICON = "icon";

    // Binder given to clients
    private final IBinder mBinder = new ForegroundBinder();

    // Partial wake lock to prevent the app from going to sleep when locked
    private PowerManager.WakeLock wakeLock;

    private String NOTIFICATION_CHANNEL_ID = "Privy Chat Service";
    /**
     * Allow clients to call on to the service.
     */
    @Override
    public IBinder onBind (Intent intent) {
        return mBinder;
    }

    /**
     * Class used for the client Binder.  Because we know this service always
     * runs in the same process as its clients, we don't need to deal with IPC.
     */
    public class ForegroundBinder extends Binder {
        ForegroundService getService() {
            // Return this instance of ForegroundService
            // so clients can call public methods
            return ForegroundService.this;
        }
    }

    /**
     * Put the service in a foreground state to prevent app from being killed
     * by the OS.
     */
    @Override
    public void onCreate () {
        super.onCreate();
        keepAwake();
    }

    /**
     * No need to run headless on destroy.
     */
    @Override
    public void onDestroy() {
        super.onDestroy();
        sleepWell();
    }

    /**
     * Put the service in a foreground state to prevent app from being killed
     * by the OS.
     */
    private void keepAwake() {
        JSONObject settings = BackgroundMode.getSettings();
        boolean isSilent    = settings.optBoolean("silent", false);

        if (!isSilent) {
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.O) {
                NotificationChannel chan = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                        getString(R.string.NOTIFICATION_BACKGROUND), NotificationManager.IMPORTANCE_MIN);
                chan.setLightColor(Color.BLUE);
                chan.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
                chan.setShowBadge(false);
                NotificationManager service = (NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE);
                service.createNotificationChannel(chan);
                startForeground(NOTIFICATION_ID, makeNotificationForHigherApi(BackgroundMode.getSettings()));
            } else {
                startForeground(NOTIFICATION_ID, makeNotification());
            }
        }

//        PowerManager powerMgr = (PowerManager)
//                getSystemService(POWER_SERVICE);
//
//        wakeLock = powerMgr.newWakeLock(
//                PowerManager.PARTIAL_WAKE_LOCK, "BackgroundMode");
//
//        wakeLock.acquire();
//        setAlarm();
    }

    private void setAlarm(){
        if (alarmMgr != null) return;
        long triggerTime = SystemClock.elapsedRealtime() + 10 * 1000;
        alarmMgr = (AlarmManager)this.getSystemService(Context.ALARM_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
            triggerTime = SystemClock.elapsedRealtime() + 5 * 60 * 1000;
            Intent intent = new Intent(getApplicationContext(), AlarmTriggerBroadcastReceiver.class);
            alarmIntent = PendingIntent.getBroadcast(getApplicationContext(), 0, intent, 0);
            alarmMgr.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerTime, alarmIntent);
        } else {
            long triggerInterval = 10 * 60 * 1000;
            Intent intent = new Intent(this, MainActivity.class);
            alarmIntent = PendingIntent.getBroadcast(this, 0, intent, 0);
            alarmMgr.setInexactRepeating(AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerTime, triggerInterval
                    , alarmIntent);
        }
    }

    /**
     * Stop background mode.
     */
    private void sleepWell() {
        stopForeground(true);
        getNotificationManager().cancel(NOTIFICATION_ID);

        if (wakeLock != null) {
            wakeLock.release();
            wakeLock = null;
        }

        if (alarmMgr != null){
            alarmMgr.cancel(alarmIntent);
            alarmMgr = null;
        }
    }

    /**
     * Create a notification as the visible part to be able to put the service
     * in a foreground state by using the default settings.
     */
    private Notification makeNotification() {
        return makeNotification(BackgroundMode.getSettings());
    }

    /**
     * Create a notification as the visible part to be able to put the service
     * in a foreground state.
     *
     * @param settings The config settings
     */
    private Notification makeNotification(JSONObject settings) {
        String title    = settings.optString("title", NOTIFICATION_TITLE);
        String text     = settings.optString("text", NOTIFICATION_TEXT);
        boolean bigText = settings.optBoolean("bigText", false);

        Context context = getApplicationContext();
        String pkgName  = context.getPackageName();
        Intent intent   = context.getPackageManager()
                .getLaunchIntentForPackage(pkgName);

        Notification.Builder notification = new Notification.Builder(context)
                .setContentTitle(title)
                .setContentText(text)
                .setOngoing(true)
                .setSmallIcon(getIconResId(settings));

        if (settings.optBoolean("hidden", true)) {
            notification.setPriority(Notification.PRIORITY_MIN);
        }

        if (bigText || text.contains("\n")) {
            notification.setStyle(
                    new Notification.BigTextStyle().bigText(text));
        }

        setColor(notification, settings);

        if (intent != null && settings.optBoolean("resume")) {
            PendingIntent contentIntent = PendingIntent.getActivity(
                    context, NOTIFICATION_ID, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT);

            notification.setContentIntent(contentIntent);
        }

        return notification.build();
    }

    /**
     * Create a notification as the visible part to be able to put the service
     * in a foreground state.
     *
     * @param settings The config settings
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private Notification makeNotificationForHigherApi(JSONObject settings) {
        String title    = settings.optString("title", NOTIFICATION_TITLE);
        String text     = settings.optString("text", NOTIFICATION_TEXT);
        boolean bigText = settings.optBoolean("bigText", false);

        Context context = getApplicationContext();
        String pkgName  = context.getPackageName();
        Intent intent   = context.getPackageManager()
                .getLaunchIntentForPackage(pkgName);

        NotificationCompat.Builder notification = new NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setOngoing(true)
                .setSmallIcon(getIconResId(settings));

        if (settings.optBoolean("hidden", true)) {
            notification.setPriority(Notification.PRIORITY_MIN);
        }

        if (bigText || text.contains("\n")) {
            notification.setStyle(
                    new NotificationCompat.BigTextStyle().bigText(text));
        }

//        setColor(notification, settings);

        if (intent != null && settings.optBoolean("resume")) {
            PendingIntent contentIntent = PendingIntent.getActivity(
                    context, NOTIFICATION_ID, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT);

            notification.setContentIntent(contentIntent);
        }

        return notification.build();
    }

    /**
     * Update the notification.
     *
     * @param settings The config settings
     */
    protected void updateNotification (JSONObject settings) {
        boolean isSilent = settings.optBoolean("silent", false);

        if (isSilent) {
            stopForeground(true);
            return;
        }

        Notification notification = null;
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.O) {
            notification = makeNotificationForHigherApi(settings);
        }else {
            notification = makeNotification(settings);
        }
        getNotificationManager().notify(
                NOTIFICATION_ID, notification);
    }

    /**
     * Retrieves the resource ID of the app icon.
     *
     * @param settings A JSON dict containing the icon name.
     */
    private int getIconResId(JSONObject settings) {
        Context context = getApplicationContext();
        Resources res   = context.getResources();
        String pkgName  = context.getPackageName();
        String icon     = settings.optString("icon", NOTIFICATION_ICON);

        // cordova-android 6 uses mipmaps
        int resId = getIconResId(res, icon, "mipmap", pkgName);

        if (resId == 0) {
            resId = getIconResId(res, icon, "drawable", pkgName);
        }

        return resId;
    }

    /**
     * Retrieve resource id of the specified icon.
     *
     * @param res The app resource bundle.
     * @param icon The name of the icon.
     * @param type The resource type where to look for.
     * @param pkgName The name of the package.
     *
     * @return The resource id or 0 if not found.
     */
    private int getIconResId(Resources res, String icon,
                             String type, String pkgName) {

        int resId = res.getIdentifier(icon, type, pkgName);

        if (resId == 0) {
            resId = res.getIdentifier("icon", type, pkgName);
        }

        return resId;
    }

    /**
     * Set notification color if its supported by the SDK.
     *
     * @param notification A Notification.Builder instance
     * @param settings A JSON dict containing the color definition (red: FF0000)
     */
    private void setColor(Notification.Builder notification,
                          JSONObject settings) {

        String hex = settings.optString("color", null);

        if (Build.VERSION.SDK_INT < 21 || hex == null)
            return;

        try {
            int aRGB = Integer.parseInt(hex, 16) + 0xFF000000;
            Method setColorMethod = notification.getClass().getMethod(
                    "setColor", int.class);

            setColorMethod.invoke(notification, aRGB);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Shared manager for the notification service.
     */
    private NotificationManager getNotificationManager() {
        return (NotificationManager) getSystemService(
                Context.NOTIFICATION_SERVICE);
    }

}
