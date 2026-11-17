package com.mh1721.handshake;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

import android.app.Activity;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class MainActivity extends Activity {
    private static final String ACTION_USB_PERMISSION = "com.mh1721.handshake.USB_PERMISSION";

    private UsbManager usbManager;
    private TextView output;
    private byte[] pendingSecret;
    private BroadcastReceiver usbPermissionReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        usbManager = (UsbManager) getSystemService(USB_SERVICE);
        output = findViewById(R.id.output);
        output.setText("The phone encrypts a 16-byte secret with the MH1721 public key.");
        findViewById(R.id.phone).setOnClickListener(v -> runPhone());
        findViewById(R.id.board).setOnClickListener(v -> startBoard());
    }

    @Override
    protected void onStart() {
        super.onStart();
        usbPermissionReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!ACTION_USB_PERMISSION.equals(intent.getAction())) {
                    return;
                }
                UsbDevice device = readDevice(intent);
                boolean granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false);
                if (device != null && granted) {
                    talk(device);
                } else {
                    output.setText("USB permission was denied.");
                }
            }
        };
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(usbPermissionReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbPermissionReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (usbPermissionReceiver != null) {
            unregisterReceiver(usbPermissionReceiver);
            usbPermissionReceiver = null;
        }
    }

    private void runPhone() {
        try {
            byte[] secret = newSecret();
            byte[] cipher = RsaBox.encrypt(secret);
            byte[] opened = RsaBox.decrypt(cipher);
            output.setText("phone\nsecret " + hex(secret)
                    + "\ncipher bytes " + cipher.length
                    + "\nopened " + hex(opened)
                    + "\nmatch " + Arrays.equals(secret, opened));
        } catch (Exception error) {
            output.setText(error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    private void startBoard() {
        try {
            pendingSecret = newSecret();
        } catch (Exception error) {
            output.setText(error.getMessage());
            return;
        }
        ArrayList<UsbDevice> devices = new ArrayList<>(usbManager.getDeviceList().values());
        if (devices.isEmpty()) {
            output.setText("No USB device. Connect the MH1721 with a USB OTG adapter.");
            return;
        }
        UsbDevice device = devices.get(0);
        if (usbManager.hasPermission(device)) {
            talk(device);
            return;
        }
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        Intent permissionIntent = new Intent(ACTION_USB_PERMISSION);
        permissionIntent.setPackage(getPackageName());
        PendingIntent permission = PendingIntent.getBroadcast(this, 0, permissionIntent, flags);
        output.setText("Asking for USB permission.");
        usbManager.requestPermission(device, permission);
    }

    private void talk(UsbDevice device) {
        byte[] secret = pendingSecret;
        output.setText("Opening " + device.getDeviceName());
        new Thread(() -> {
            String text;
            try (BoardLink link = BoardLink.open(usbManager, device)) {
                Frames.PublicKey pub = Frames.parsePublic(link.transact(Frames.request(Frames.HELLO, null)));
                boolean modulusMatches = Arrays.equals(strip(pub.modulus), RsaBox.modulus());
                boolean exponentMatches = Arrays.equals(strip(pub.exponent), RsaBox.publicExponent());
                byte[] cipher = RsaBox.encrypt(secret);
                byte[] opened = link.transact(Frames.request(Frames.OPEN, cipher));
                text = "board\nmodulus matches " + modulusMatches
                        + "\nexponent matches " + exponentMatches
                        + "\nsecret " + hex(secret)
                        + "\nopened " + hex(opened)
                        + "\nmatch " + Arrays.equals(secret, opened);
            } catch (Exception error) {
                text = error.getClass().getSimpleName() + ": " + error.getMessage();
            }
            String show = text;
            runOnUiThread(() -> output.setText(show));
        }).start();
    }

    private static byte[] newSecret() {
        byte[] secret = new byte[16];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    private static byte[] strip(byte[] value) {
        int start = 0;
        while (start < value.length - 1 && value[start] == 0) {
            start++;
        }
        if (start == 0) {
            return value;
        }
        return Arrays.copyOfRange(value, start, value.length);
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }

    private static UsbDevice readDevice(Intent intent) {
        if (Build.VERSION.SDK_INT >= 33) {
            return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class);
        }
        return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
    }
}
