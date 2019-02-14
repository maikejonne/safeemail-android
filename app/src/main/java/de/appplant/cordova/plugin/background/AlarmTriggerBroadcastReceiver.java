package de.appplant.cordova.plugin.background;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

import static org.apache.cordova.device.Device.TAG;

public class AlarmTriggerBroadcastReceiver extends BroadcastReceiver {

    private AlarmManager alarmMgr;
    private PendingIntent alarmIntent;

    @Override
    public void onReceive(Context context, Intent intent) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
            long triggerTime = SystemClock.elapsedRealtime() + 10 * 60 * 1000;
            alarmMgr = (AlarmManager)context.getSystemService(Context.ALARM_SERVICE);
            Intent broadIntent = new Intent(context, AlarmTriggerBroadcastReceiver.class);
            alarmIntent = PendingIntent.getBroadcast(context, 0, broadIntent, 0);
            alarmMgr.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerTime, alarmIntent);

            Log.d(TAG, "=============>received alarm!");
        }
    }
}
