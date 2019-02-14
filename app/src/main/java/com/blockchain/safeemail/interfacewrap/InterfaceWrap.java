/*
 Copyright 2014 Modern Alchemists OG

 Licensed under MIT.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
 to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/

package com.blockchain.safeemail.interfacewrap;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.media.MediaMetadataRetriever;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.support.v4.content.FileProvider;
import android.util.Log;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.blockchain.safeemail.BuildConfig;
import com.blockchain.safeemail.R;
import com.github.hiteshsondhi88.libffmpeg.ExecuteBinaryResponseHandler;
import com.github.hiteshsondhi88.libffmpeg.FFmpeg;
import com.github.hiteshsondhi88.libffmpeg.LoadBinaryResponseHandler;
import com.github.hiteshsondhi88.libffmpeg.exceptions.FFmpegCommandAlreadyRunningException;
import com.github.hiteshsondhi88.libffmpeg.exceptions.FFmpegNotSupportedException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PermissionHelper;
import org.apache.cordova.PluginResult;
import org.apache.cordova.file.FileUtils;
import org.apache.cordova.file.Filesystem;
import org.apache.xerces.impl.dv.util.Base64;
import org.bitcoin.NativeBlowfish;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoin.NativeSecp256k1Wrap;
import org.bitcoin.Sha256Hash;
import org.bitcoin.Utils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.security.DigestOutputStream;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.flexiprovider.common.util.ByteUtils;
import pub.devrel.easypermissions.EasyPermissions;

@TargetApi(19)
public class InterfaceWrap extends CordovaPlugin {
    private static final int PRIVATEKEY_LENGTH = 32;
    private static final int PUBLICKEY_LENGTH = 33;
    private static final String DIRECTORY_NAME = "SafeEmail";
    private CallbackContext callbackContext;
    private List<UserInfo> m_UserInfos;
    private UserInfo m_CurrentUser;
    private boolean m_IsFFmpegEnabled;
    private FFmpeg m_FFmpeg;

    public InterfaceWrap() {
        m_UserInfos = new ArrayList<UserInfo>();
    }

    public static void saveImage(String path) {
        path = Uri.parse(path).getPath();
        File file = new File(path);
        if (!file.exists()) return;
        String rootDir = Environment.getExternalStorageDirectory().getPath() + "/" + DIRECTORY_NAME + "/Images/";
        try {
            File rootDirFile = new File(rootDir);
            if (!rootDirFile.exists()) {
                if (!rootDirFile.mkdirs())
                    throw new IOException("Cannot create " + DIRECTORY_NAME + " directories");
            }
            String extension = "";
            int i = path.lastIndexOf('.');
            if (i > 0) {
                extension = path.substring(i + 1);
            }
            if (extension.isEmpty()) {
                throw new Exception("path extension error");
            }
            long timeStamp = System.currentTimeMillis();
            String fileName = timeStamp + "." + extension;
            File destFile = new File(rootDirFile, fileName);
            if (destFile.exists())
                destFile.delete();

            FileChannel src = new FileInputStream(file).getChannel();
            FileChannel dest = new FileOutputStream(destFile).getChannel();
            dest.transferFrom(src, 0, src.size());
        } catch (IOException e) {
            Log.d("Save Image", "Save Image IO error: " + e.getMessage());
        } catch (Exception e) {
            Log.d("Save Image", "Save Image error: " + e.getMessage());
        }
    }

    private FFmpeg getFFmpeg() {
        if (m_IsFFmpegEnabled) {
            return m_FFmpeg;
        }
        return null;
    }

    private void initFFmpeg() {
        m_FFmpeg = FFmpeg.getInstance(cordova.getActivity());
        try {
            m_FFmpeg.loadBinary(new LoadBinaryResponseHandler() {
                @Override
                public void onFailure() {
                    m_IsFFmpegEnabled = false;
                }

                @Override
                public void onSuccess() {
                    m_IsFFmpegEnabled = true;
                }
            });
        } catch (FFmpegNotSupportedException e) {
            m_IsFFmpegEnabled = false;
        }
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        initFFmpeg();
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        this.callbackContext = callbackContext;
        final InterfaceWrap self = this;

        if (action.equals("isIgnoringBatteryOptimizations")) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        boolean isIgnored = isIgnoringBatteryOptimizations();
                        // send success result to cordova
                        PluginResult result = new PluginResult(PluginResult.Status.OK, isIgnored ? 1 : 0);
                        self.callbackContext.sendPluginResult(result);
                    } catch (Exception e) {
                        // return error answer to cordova
                        PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.getMessage());
                        self.callbackContext.sendPluginResult(result);
                    }
                }
            });
            return true;
        } else if (action.equals("internetWhiteListRequest")) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        forbidInternetRequestDialog();
                        // send success result to cordova
                        PluginResult result = new PluginResult(PluginResult.Status.OK);
                        self.callbackContext.sendPluginResult(result);
                    } catch (Exception e) {
                        // return error answer to cordova
                        PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.getMessage());
                        self.callbackContext.sendPluginResult(result);
                    }
                }
            });
            return true;
        } else if (action.equals("tryLogin")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        tryLogin(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("generatePrivateKey")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        initUserKeyPairs();
                        writePrivateKeyFile();
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, createReturnUserData()));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("decryptPrivateKey")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        decryptPrivateKey(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("revertPrivateKeyLevel")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        revertPrivateKeyLevel(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("encryptPrivateKey")) {
            String pw = args.getString(0);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        writePrivateKeyFile(pw);
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("ECIESDecrypt")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            int index = args.getInt(1);
            if (index < 0 || index >= m_UserInfos.size()) {
                callbackContext.error("user info index error!");
                return true;
            }
            String dataStr = args.getString(0);
            int keyPairType = args.getInt(2);
            byte[] cipherBytes = Base64.decode(dataStr);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        UserInfo user = m_UserInfos.get(index);
                        byte[] privateKeyBytes = user.KeyPairs.get(keyPairType).first;
                        byte[] rawBytes = ECIESDecrypt(privateKeyBytes, cipherBytes);
                        callbackContext.success(new String(rawBytes));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("ECIESEncrypt")) {
            byte[] pubkey = Base64.decode(args.getString(0));
            String dataStr = args.getString(1);
            byte[] dataBytes = dataStr.getBytes();
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] cipherBytes = ECIESEncrypt(pubkey, dataBytes);
                        callbackContext.success(Base64.encode(cipherBytes));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("ECIESEncryptSelf")) {
            if (m_CurrentUser == null || m_CurrentUser.KeyPairs.size() <= 0) {
                callbackContext.error("current user private key array is null or bad length!");
                return true;
            }
            String dataStr = args.getString(0);
            int keyPairType = args.getInt(1);
            byte[] dataBytes = dataStr.getBytes();
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] cipherBytes = ECIESEncrypt(getKeyPairByType(keyPairType).second, dataBytes);
                        callbackContext.success(Base64.encode(cipherBytes));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("exportPrivateKey")) {
            showExportView(args, callbackContext);
            return true;
        } else if (action.equals("loginFromFile")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        loginFromFile(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("sign")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            byte[] data = Base64.decode(args.getString(0));
            int userIndex = args.getInt(1);
            int keyPairType = args.getInt(2);
            final byte[] hashData = Sha256Hash.hash(data);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        UserInfo user = m_UserInfos.get(userIndex);
                        byte[] privateKey = user.KeyPairs.get(keyPairType).first;
                        byte[] signature = NativeSecp256k1.sign(hashData, privateKey);
                        callbackContext.success(new JSONArray(signature));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("sign_recoverable")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            byte[] data = Base64.decode(args.getString(0));
            int userIndex = args.getInt(1);
            int keyPairType = args.getInt(2);
            final byte[] hashData = Sha256Hash.hash(data);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        UserInfo user = m_UserInfos.get(userIndex);
                        byte[] privateKey = user.KeyPairs.get(keyPairType).first;
                        byte[] rsignature = NativeSecp256k1.sign_recoverable(hashData, privateKey);
                        callbackContext.success(Base64.encode(rsignature));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("computePubkey")) {
            if (m_CurrentUser == null || m_CurrentUser.KeyPairs.size() <= 0) {
                callbackContext.error("current user private key array is null or bad length!");
                return true;
            }
            int keyPairType = args.getInt(0);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] privateKey = m_CurrentUser.KeyPairs.get(keyPairType).first;
                        byte[] pubkey = NativeSecp256k1.computePubkey(privateKey);
                        callbackContext.success(Base64.encode(pubkey));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("removePrivateKey")) {
            m_UserInfos.remove(m_CurrentUser);
            if (m_UserInfos.size() > 0)
                m_CurrentUser = m_UserInfos.get(0);
            callbackContext.success();
            return true;
        } else if (action.equals("encryptDataByFile")) {
            if (hasReadPermission() && hasWritePermission()) {
                cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        try {
                            encryptDataByFile(args, callbackContext);
                        } catch (Exception e) {
                            callbackContext.error(e.getMessage());
                        }
                    }
                });
            } else if (hasReadPermission()) {
                PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
            } else {
                PermissionHelper.requestPermission(this, 1, Manifest.permission.READ_EXTERNAL_STORAGE);
            }
            return true;
        } else if (action.equals("decryptDataByFile")) {
            if (hasReadPermission() && hasWritePermission()) {
                cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        try {
                            decryptDataByFile(args, callbackContext);
                        } catch (Exception e) {
                            callbackContext.error(e.getMessage());
                        }
                    }
                });
            } else if (hasReadPermission()) {
                PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
            } else {
                PermissionHelper.requestPermission(this, 1, Manifest.permission.READ_EXTERNAL_STORAGE);
            }
            return true;
        } else if (action.equals("getCurrentUserIndex")) {
            if (m_CurrentUser == null || m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("current user info is null!");
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        callbackContext.success(m_UserInfos.indexOf(m_CurrentUser));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("setCurrentUserIndex")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            int index = args.getInt(0);
            if (index < 0 || index >= m_UserInfos.size()) {
                callbackContext.error("user info index error!");
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        m_CurrentUser = m_UserInfos.get(index);
                        if (m_CurrentUser == null)
                            throw new Exception("current user info is null!");
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("generateNewUser")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        m_UserInfos.add(generateNewUser());
                        writePrivateKeyFile();
                        callbackContext.success(createReturnUserData());
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("generateSubKeyPair")) {
            if (m_CurrentUser == null || m_CurrentUser.KeyPairs.size() <= 0) {
                callbackContext.error("current user private key array is null or bad length!");
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        generateSubKeyPair();
                        writePrivateKeyFile();
                        callbackContext.success(createReturnSingleUserData(m_CurrentUser));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("addNewUser")) {
            String rawData = args.getString(0);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        decodeSingleUserJson(new JSONObject(rawData));
                        writePrivateKeyFile();
                        callbackContext.success(createReturnUserData());
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("removeUser")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            int index = args.getInt(0);
            if (index < 0 || index >= m_UserInfos.size()) {
                callbackContext.error("user info index error!");
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        m_UserInfos.remove(index);
                        writePrivateKeyFile();
                        callbackContext.success(createReturnUserData());
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("modifyUserLabel")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            int index = args.getInt(0);
            if (index < 0 || index >= m_UserInfos.size()) {
                callbackContext.error("user info index error!");
                return true;
            }
            String label = args.getString(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        UserInfo user = m_UserInfos.get(index);
                        user.Label = label;
                        writePrivateKeyFile();
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("modifyUserHost")) {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("user info array is null or bad length!");
                return true;
            }
            int index = args.getInt(0);
            if (index < 0 || index >= m_UserInfos.size()) {
                callbackContext.error("user info index error!");
                return true;
            }
            String host = args.getString(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        UserInfo user = m_UserInfos.get(index);
                        user.Host = host;
                        writePrivateKeyFile();
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("copyToClipBoard")) {
            cordova.getThreadPool().execute(new Runnable() {
                String text = args.getString(0);
                public void run() {
                    try {
                        copyToClipBoard(text);
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("compressVideo")) {
            if (!hasWritePermission()) {
                PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        compressVideo(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("compressAudio")) {
            if (!hasWritePermission()) {
                PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        compressAudio(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("downloadFile")) {
            if (!hasWritePermission()) {
                PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        downloadFile(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("combineFile")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        combineFile(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("getCurrentLocale")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    getCurrentLocale(args, callbackContext);
                }
            });
            return true;
        } else if (action.equals("hasRecordAudioPermission")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    callbackContext.success(hasRecordAudioPermission() ? 1 : 0);
                }
            });
            return true;
        } else if (action.equals("getAudioDuration")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        getAudioDuration(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("getFileLength")) {
            if (!hasReadPermission()) {
                PermissionHelper.requestPermission(this, 1, Manifest.permission.READ_EXTERNAL_STORAGE);
                return true;
            }
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String path = args.getString(0);
                        if (path == null || path.isEmpty()) {
                            callbackContext.error("file path not exist!");
                            return;
                        }
                        path = Uri.parse(path).getPath();
                        File file = new File(path);
                        if (!file.exists()) {
                            callbackContext.error("file not exist!");
                            return;
                        }
                        callbackContext.success(String.valueOf(file.length()));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("startInstallApk")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String path = args.getString(0);
                        if (path == null || path.isEmpty()) {
                            callbackContext.error("file path not exist!");
                            return;
                        }
                        path = Uri.parse(path).getPath();
                        File file = new File(path);
                        if (!file.exists()) {
                            callbackContext.error("apk file not exist!");
                            return;
                        }
                        Uri uri = FileProvider.getUriForFile(cordova.getContext(), cordova.getContext().getApplicationContext().getPackageName() + ".GenericFileProvider", file);
                        Intent promptInstall = new Intent(Intent.ACTION_VIEW)
                                .setDataAndType(uri,
                                        "application/vnd.android.package-archive");
                        promptInstall.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                        cordova.getActivity().startActivity(promptInstall);
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("hasExternalStoragePermission")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        callbackContext.success((hasWritePermission() && hasReadPermission()) ? 1 : 0);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("requestExternalStoragePermission")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        if (!hasReadPermission())
                            EasyPermissions.requestPermissions(cordova.getActivity(), cordova.getContext().getString(R.string.READ_EXTERNAL_STORAGE), 119, Manifest.permission.READ_EXTERNAL_STORAGE);
                        else
                            EasyPermissions.requestPermissions(cordova.getActivity(), cordova.getContext().getString(R.string.READ_EXTERNAL_STORAGE), 118, Manifest.permission.WRITE_EXTERNAL_STORAGE);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("requestAudioPermission")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        if (!hasRecordAudioPermission())
                            EasyPermissions.requestPermissions(cordova.getActivity(), "Privy Chat May Need your Audio Permission to Record", 117, Manifest.permission.RECORD_AUDIO);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("getVersionCode")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        callbackContext.success(BuildConfig.VERSION_CODE);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("createDirectorys")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String path = args.getString(0);
                        if (path == null || path.isEmpty()) {
                            callbackContext.error("file path not exist!");
                            return;
                        }
                        path = Uri.parse(path).getPath();
                        File file = new File(path);
                        if (!file.exists()) {
                            if (!file.mkdirs()) {
                                callbackContext.error("create directory failed!");
                                return;
                            }
                        }
                        callbackContext.success();
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        return false;
    }

    private boolean isIgnoringBatteryOptimizations() throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            String packageName = cordova.getContext().getApplicationContext().getPackageName();
            PowerManager pm = (PowerManager) cordova.getContext().getSystemService(Context.POWER_SERVICE);
            boolean result = pm.isIgnoringBatteryOptimizations(packageName);
            return result;
        }
        return true;
    }

    private void forbidInternetRequestDialog() throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            String packageName = cordova.getContext().getApplicationContext().getPackageName();
            if (!isIgnoringBatteryOptimizations()) {
                //方法一，弹系统对话框请求
                Intent intent = new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).setData(Uri.parse("package:" + packageName));
                intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
                cordova.getContext().startActivity(intent);
                //方法二，跳到相应的设置页面用户自己去设置
//                cordova.getContext().startActivity(new Intent("android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS"));
                //方法二，请求权限
                // requestPermissions(new String[]{"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"}, REQUEST_CODE_ASK_PERMISSIONS);
            }
        }
    }

    private void generateSubKeyPair() throws Exception {
        if (m_CurrentUser == null)
            throw new Exception("Current User is not exist!");
        if (m_CurrentUser.KeyPairs == null) {
            m_CurrentUser.KeyPairs = new HashMap<>();
        }
        m_CurrentUser.KeyPairs.put(m_CurrentUser.KeyPairs.size(), generateECKeyPair());
    }

    private Pair<byte[], byte[]> generateECKeyPair() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        kpg.initialize(ecSpec);
        java.security.KeyPair kp = kpg.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic();

        byte[] privateKeyBytes = privateKey.getD().toByteArray();
        byte[] publicKeyBytes = publicKey.getQ().getEncoded(true);

        if (privateKeyBytes[0] == 0) {
            byte[] tmp = new byte[privateKeyBytes.length - 1];
            System.arraycopy(privateKeyBytes, 1, tmp, 0, tmp.length);
            privateKeyBytes = tmp;
        }

        if (privateKeyBytes.length != PRIVATEKEY_LENGTH) {
            throw new Exception("generate private key length error");
        }

        return new Pair<>(privateKeyBytes, publicKeyBytes);
    }

    private void initUserKeyPairs() throws Exception {
        m_UserInfos.clear();
        m_CurrentUser = generateNewUser();
        m_UserInfos.add(m_CurrentUser);
    }

    private UserInfo generateNewUser() throws Exception {
        UserInfo user = new UserInfo();
        user.Label = "";
        user.Host = "";
        user.KeyPairs = new HashMap<>();
        user.KeyPairs.put(0, generateECKeyPair());
        user.KeyPairs.put(1, generateECKeyPair());
        user.KeyPairs.put(2, generateECKeyPair());
        return user;
    }

    private Pair<byte[], byte[]> getKeyPairByType(int keyPairType) {
        if (m_CurrentUser == null || m_CurrentUser.KeyPairs.size() <= 0) return null;
        if (!m_CurrentUser.KeyPairs.containsKey(keyPairType)) return null;
        return m_CurrentUser.KeyPairs.get(keyPairType);
    }

    private void tryLogin(JSONArray args, CallbackContext callbackContext) throws Exception {
        Context context = cordova.getActivity();
        //applicationStorageDirectory
        Uri uri = Uri.fromFile(context.getFilesDir().getParentFile());
        uri = Uri.parse(uri.toString() + "/privatekey.keystore");
        FileUtils.getFilePlugin().TryReadFile(uri, args, callbackContext, new NativeSecp256k1Wrap.ReadFileCallback() {
            @Override
            public void handleData(byte[] content) {
                try {
                    JSONObject result = new JSONObject(new String(content));
                    if (result.getInt("type") == 1) {
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, 1));
                    } else {
                        decodeUserArrayJson(result.getJSONArray("users"));
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, createReturnUserData()));
                    }
                } catch (JSONException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.JSON_EXCEPTION));
                } catch (NativeSecp256k1Util.AssertFailException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private void decodeSingleUserJson(JSONObject userRawData) throws Exception {
        UserInfo user = new UserInfo();
        user.Label = userRawData.getString("label");
        user.Host = userRawData.getString("host");
        user.KeyPairs = new HashMap<>();
        JSONArray privateKeys = userRawData.getJSONArray("privateKeyArray");
        for (int j = 0; j < privateKeys.length(); j++) {
            byte[] privateKey = Base64.decode(privateKeys.getString(j));
            if (privateKey == null || privateKey.length < PRIVATEKEY_LENGTH) {
                throw new Exception("decode private key failed, result is null or bad length!");
            }
            byte[] publicKey = NativeSecp256k1.computePubkey(privateKey);
            user.KeyPairs.put(j, new Pair<>(privateKey, publicKey));
        }
        m_UserInfos.add(user);
    }

    private void decodeUserArrayJson(JSONArray json) throws Exception {
        if (json.length() <= 0)
            throw new Exception("decode user info array length error");
        for (int i = 0; i < json.length(); i++) {
            JSONObject userRawData = json.getJSONObject(i);
            decodeSingleUserJson(userRawData);
        }
        m_CurrentUser = m_UserInfos.get(0);
    }

    private void decodeUserArrayJson(JSONArray json, String pw) throws Exception {
        if (json.length() <= 0)
            throw new Exception("decode user info array length error");
        for (int i = 0; i < json.length(); i++) {
            JSONObject userRawData = json.getJSONObject(i);
            UserInfo user = new UserInfo();
            user.Label = userRawData.getString("label");
            user.Host = userRawData.getString("host");
            user.KeyPairs = new HashMap<>();
            JSONArray privateKeys = userRawData.getJSONArray("privateKeyArray");
            for (int j = 0; j < privateKeys.length(); j++) {
                byte[] privateKey = NativeBlowfish.decrypt(Base64.decode(privateKeys.getString(j)), pw.getBytes());
                if (privateKey == null || privateKey.length < PRIVATEKEY_LENGTH) {
                    throw new Exception("decode private key failed, result is null or bad length!");
                }
                byte[] publicKey = NativeSecp256k1.computePubkey(privateKey);
                user.KeyPairs.put(j, new Pair<>(privateKey, publicKey));
            }
            m_UserInfos.add(user);
        }
        m_CurrentUser = m_UserInfos.get(0);
    }

    private void writePrivateKeyFile() throws Exception {
        if (m_UserInfos == null || m_UserInfos.size() <= 0) {
            throw new Exception("user info array length error");
        }
        JSONObject json = new JSONObject();
        json.put("type", 0);
        JSONArray users = new JSONArray();
        for (int i = 0; i < m_UserInfos.size(); i++) {
            UserInfo user = m_UserInfos.get(i);
            JSONObject userObj = new JSONObject();
            userObj.put("label", user.Label);
            userObj.put("host", user.Host);
            JSONArray privateKeyArray = new JSONArray();
            for (int j = 0; j < user.KeyPairs.size(); j++) {
                if (user.KeyPairs.get(j).first == null || user.KeyPairs.get(j).first.length < PRIVATEKEY_LENGTH)
                    throw new Exception("private key length error");
                privateKeyArray.put(Base64.encode(user.KeyPairs.get(j).first));
            }
            userObj.put("privateKeyArray", privateKeyArray);
            users.put(userObj);
        }
        json.put("users", users);
        Context context = cordova.getActivity();
        Uri rootDir = Uri.fromFile(context.getFilesDir().getParentFile());
        FileUtils.getFilePlugin().TryWriteFile(rootDir, "privatekey.keystore", json.toString());
    }

    private void writePrivateKeyFile(String pw) throws Exception {
        if (m_UserInfos == null || m_UserInfos.size() <= 0) {
            throw new Exception("user info array length error");
        }
        JSONObject json = new JSONObject();
        json.put("type", 1);
        JSONArray users = new JSONArray();
        for (int i = 0; i < m_UserInfos.size(); i++) {
            UserInfo user = m_UserInfos.get(i);
            JSONObject userObj = new JSONObject();
            userObj.put("label", user.Label);
            userObj.put("host", user.Host);
            JSONArray privateKeyArray = new JSONArray();
            for (int j = 0; j < user.KeyPairs.size(); j++) {
                if (user.KeyPairs.get(j).first == null || user.KeyPairs.get(j).first.length < PRIVATEKEY_LENGTH)
                    throw new Exception("private key length error");
                privateKeyArray.put(Base64.encode(NativeBlowfish.encrypt(user.KeyPairs.get(j).first, pw.getBytes())));
            }
            userObj.put("privateKeyArray", privateKeyArray);
            users.put(userObj);
        }
        json.put("users", users);
        Context context = cordova.getActivity();
        Uri rootDir = Uri.fromFile(context.getFilesDir().getParentFile());
        FileUtils.getFilePlugin().TryWriteFile(rootDir, "privatekey.keystore", json.toString());
    }

    private JSONArray createReturnUserData() throws Exception {
        JSONArray array = new JSONArray();
        for (int i = 0; i < m_UserInfos.size(); i++) {
            JSONObject userObj = createReturnSingleUserData(m_UserInfos.get(i));
            array.put(userObj);
        }
        return array;
    }

    private JSONObject createReturnSingleUserData(UserInfo user) throws Exception {
        JSONObject userObj = new JSONObject();
        userObj.put("label", user.Label);
        userObj.put("host", user.Host);
        JSONArray publicKeys = new JSONArray();
        for (int j = 0; j < user.KeyPairs.size(); j++) {
            publicKeys.put(Base64.encode(user.KeyPairs.get(j).second));
        }
        userObj.put("publicKeyArray", publicKeys);
        return userObj;
    }

    private void decryptPrivateKey(JSONArray args, CallbackContext callbackContext) throws Exception {
        Context context = cordova.getActivity();
        //applicationStorageDirectory
        Uri uri = Uri.fromFile(context.getFilesDir().getParentFile());
        uri = Uri.parse(uri.toString() + "/privatekey.keystore");
        String pw = args.getString(0);
        if (pw.isEmpty()) {
            throw new Exception("password is empty!");
        }
        FileUtils.getFilePlugin().TryReadFile(uri, args, callbackContext, new NativeSecp256k1Wrap.ReadFileCallback() {
            @Override
            public void handleData(byte[] content) {
                try {
                    JSONObject result = new JSONObject(new String(content));
                    decodeUserArrayJson(result.getJSONArray("users"), pw);
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, createReturnUserData()));
                } catch (JSONException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.JSON_EXCEPTION));
                } catch (NativeSecp256k1Util.AssertFailException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private void revertPrivateKeyLevel(JSONArray args, CallbackContext callbackContext) throws Exception {
        try {
            writePrivateKeyFile();
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK));
        } catch (NativeSecp256k1Util.AssertFailException e) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
        }
    }

    private byte[] ECIESDecrypt(byte[] seckey, byte[] cipherBytes) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, 16);
        byte[] ephemPublicKey = Arrays.copyOfRange(cipherBytes, 16, 16 + 65);
        byte[] encryptText = Arrays.copyOfRange(cipherBytes, 16 + 65, cipherBytes.length - 32);
        byte[] passMac = Arrays.copyOfRange(cipherBytes, cipherBytes.length - 32, cipherBytes.length);

        KeyFactory kf2 = KeyFactory.getInstance("EC", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.jce.spec.ECPrivateKeySpec privSpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(1, seckey), ecSpec);
        PrivateKey privateKey = kf2.generatePrivate(privSpec);

        org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(ecSpec.getCurve().decodePoint(ephemPublicKey), ecSpec);
        PublicKey publicKey = kf2.generatePublic(publicKeySpec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        byte[] secretKey = ka.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA512");
        byte[] hash = md.digest(secretKey);
        byte[] encryptionKey = Arrays.copyOfRange(hash, 0, 32);
        byte[] macKey = Arrays.copyOfRange(hash, hash.length - 32, hash.length);
        byte[] dataToMac = Arrays.copyOfRange(cipherBytes, 0, cipherBytes.length - 32);

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKey sMackey = new SecretKeySpec(macKey, "HmacSHA256");
        mac.init(sMackey);
        byte[] realMac = mac.doFinal(dataToMac);

        if (!Arrays.equals(passMac, realMac)) {
            throw new Exception("decryption bad mac!");
        }
        SecretKey sEncryptkey = new SecretKeySpec(encryptionKey, "AES_256/CBC/NoPadding");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sEncryptkey, ivSpec);
        return cipher.doFinal(encryptText);
    }

    private byte[] ECIESEncrypt(byte[] pubkey, byte[] data) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyFactory kf2 = KeyFactory.getInstance("EC", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(ecSpec.getCurve().decodePoint(pubkey), ecSpec);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) kf2.generatePublic(publicKeySpec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        kpg.initialize(ecSpec);
        java.security.KeyPair kp = kpg.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPrivateKey ephemPrivateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate();
        org.bouncycastle.jce.interfaces.ECPublicKey ephemPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ka.init(ephemPrivateKey);
        ka.doPhase(publicKey, true);
        byte[] secretKey = ka.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA512");
        byte[] hash = md.digest(secretKey);
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        byte[] encryptionKey = Arrays.copyOfRange(hash, 0, 32);
        byte[] macKey = Arrays.copyOfRange(hash, hash.length - 32, hash.length);

        SecretKey sEncryptkey = new SecretKeySpec(encryptionKey, "AES_256/CBC/PKCS5Padding");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sEncryptkey, ivSpec);
        byte[] cipherText = cipher.doFinal(data);
        byte[] dataToMac = new byte[16 + 65 + cipherText.length];
        byte[] ephemPublicKeyBytes = ephemPublicKey.getQ().getEncoded(false);
        System.arraycopy(iv, 0, dataToMac, 0, 16);
        System.arraycopy(ephemPublicKeyBytes, 0, dataToMac, 16, ephemPublicKeyBytes.length);
        System.arraycopy(cipherText, 0, dataToMac, 16 + ephemPublicKeyBytes.length, cipherText.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKey sMackey = new SecretKeySpec(macKey, "HmacSHA256");
        mac.init(sMackey);
        byte[] realMac = mac.doFinal(dataToMac);

        byte[] result = new byte[16 + ephemPublicKeyBytes.length + cipherText.length + realMac.length];
        System.arraycopy(dataToMac, 0, result, 0, dataToMac.length);
        System.arraycopy(realMac, 0, result, dataToMac.length, realMac.length);
        return result;
    }

    private void exportPrivateKey(String pw, JSONArray args, CallbackContext callbackContext) throws Exception {
        try {
            if (m_UserInfos == null || m_UserInfos.size() <= 0) {
                callbackContext.error("private key array is null or bad length!");
                return;
            }
            String rootDir = args.getString(0);
            rootDir = Uri.parse(rootDir).getPath();
            File rootDirFile = new File(rootDir);
            if (!rootDirFile.exists()) {
                if (!rootDirFile.mkdir())
                    throw new IOException("Cannot create target directory:" + rootDir);
            }
            writePrivateKeyFile(pw);
            String destFileName = "!!!IMPORTANT!!!.TXT";
            File destFile = new File(rootDirFile, destFileName);
            Context context = cordova.getActivity();
            //applicationStorageDirectory
            File defaultPrivateKeyFile = new File(context.getFilesDir().getParentFile(), "privatekey.keystore");
            FileChannel inChannel = new FileInputStream(defaultPrivateKeyFile).getChannel();
            FileChannel outChannel = new FileOutputStream(destFile).getChannel();
            inChannel.transferTo(0, inChannel.size(), outChannel);
            inChannel.close();
            outChannel.close();
            defaultPrivateKeyFile.delete();
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, "file://" + rootDir + destFileName));
        } catch (Exception e) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
        }
    }

    private void loginFromFile(JSONArray args, CallbackContext callbackContext) throws Exception {
        String path = args.getString(0);
        Uri uri = Uri.parse(path);
        FileUtils.getFilePlugin().TryReadFile(uri, args, callbackContext, new NativeSecp256k1Wrap.ReadFileCallback() {
            @Override
            public void handleData(byte[] content) {
                try {
                    JSONObject result = new JSONObject(new String(content));
                    decodeUserArrayJson(result.getJSONArray("users"));
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, createReturnUserData()));
                } catch (NativeSecp256k1Util.AssertFailException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (JSONException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private boolean hasReadPermission() {
        return PermissionHelper.hasPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE);
    }

    private boolean hasWritePermission() {
        return PermissionHelper.hasPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE);
    }

    private boolean hasRecordAudioPermission() {
        return PermissionHelper.hasPermission(this, Manifest.permission.RECORD_AUDIO);
    }

    private void encryptDataByFile(JSONArray args, CallbackContext callbackContext) throws Exception {
        String pw = args.getString(0);
        String path = args.getString(1);
        Uri uri = Uri.parse(path);
        FileUtils.getFilePlugin().TryReadFileByChunk(uri, args, callbackContext, new Filesystem.ReadFileCallback() {
            @Override
            public void handleData(InputStream inputStream, String contentType) {
                try {
                    String rootDir = Environment.getExternalStorageDirectory().getPath() + "/" + DIRECTORY_NAME + "/";
                    File rootDirFile = new File(rootDir);
                    if (!rootDirFile.exists()) {
                        if (!rootDirFile.mkdir())
                            throw new IOException("Cannot create SecretTalk directory");
                    }
                    File tempFile = new File(rootDir, "EncryptFile.temp");
                    if (!tempFile.exists()) {
                        if (!tempFile.createNewFile()) {
                            throw new IOException("Cannot create temp file");
                        }
                    }
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(tempFile));
                    final int BUFFER_SIZE = 1048576;
                    final int HEADER_SIZE = 256;
                    String headerBase64 = "";
                    byte[] tmp = new byte[BUFFER_SIZE];
                    BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    DigestOutputStream dis = new DigestOutputStream(bufferedOutputStream, md);
                    byte[] outLength = new byte[4];

                    int outputTotalSize = 0;
                    { //separate first 600 result bytes not write into dest file
                        bufferedInputStream.read(tmp, 0, BUFFER_SIZE);
                        byte[] encrypted = NativeBlowfish.encrypt(tmp, pw.getBytes());
                        Utils.uint32ToByteArrayLE(encrypted.length, outLength, 0);
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        outputStream.write(outLength);
                        outputStream.write(encrypted, 0, HEADER_SIZE - outLength.length);
                        byte[] header = outputStream.toByteArray();
                        headerBase64 = Base64.encode(header);
                        dis.write(encrypted, HEADER_SIZE - outLength.length, encrypted.length - HEADER_SIZE + outLength.length);
                        outputTotalSize += encrypted.length - HEADER_SIZE + outLength.length;
                    }

                    while (bufferedInputStream.available() > 0) {
                        bufferedInputStream.read(tmp, 0, BUFFER_SIZE);
                        byte[] encrypted = NativeBlowfish.encrypt(tmp, pw.getBytes());
                        Utils.uint32ToByteArrayLE(encrypted.length, outLength, 0);
                        dis.write(outLength);
                        dis.write(encrypted);
                        outputTotalSize += outLength.length;
                        outputTotalSize += encrypted.length;
                    }
                    dis.flush();
                    String md5 = ByteUtils.toHexString(md.digest());
                    String path = rootDir + "/" + md5 + ".json";

                    File resultFile = new File(path);
                    if (resultFile.exists()) {
                        if (!resultFile.delete()) {
                            throw new IOException("Cannot delete same name file");
                        }
                    }
                    if (!tempFile.renameTo(resultFile)) {
                        throw new IOException("Cannot rename file");
                    }
                    dis.close();
                    bufferedInputStream.close();
                    bufferedOutputStream.close();
                    JSONArray out = new JSONArray();
                    out.put("file://" + path);
                    out.put(md5);
                    out.put(headerBase64);
                    out.put(outputTotalSize);
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, out));
                } catch (NativeSecp256k1Util.AssertFailException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (IOException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private void decryptDataByFile(JSONArray args, CallbackContext callbackContext) throws Exception {
        String pw = args.getString(0);
        String path = args.getString(1);
        String rootDir = args.getString(2);
        rootDir = Uri.parse(rootDir).getPath();
        String destFileName = args.getString(3);
        Uri uri = Uri.parse(path);
        File rootDirFile = new File(rootDir);
        if (!rootDirFile.exists()) {
            if (!rootDirFile.mkdir())
                throw new IOException("Cannot create SecretTalk directory");
        }
        String outputPath = rootDir + destFileName;
        FileUtils.getFilePlugin().TryReadFileByChunk(uri, args, callbackContext, new Filesystem.ReadFileCallback() {
            @Override
            public void handleData(InputStream inputStream, String contentType) {
                try {
                    File tempFile = new File(rootDirFile, "DecryptFile.temp");
                    if (!tempFile.exists()) {
                        if (!tempFile.createNewFile()) {
                            throw new IOException("Cannot create temp file");
                        }
                    }
                    final int BUFFER_SIZE = 1048576 + 8;
                    byte[] tmp = new byte[BUFFER_SIZE];
                    BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(tempFile));
                    while (bufferedInputStream.available() > 0) {
                        bufferedInputStream.read(tmp, 0, 4);
                        int encryptLength = (int) Utils.readUint32(tmp, 0);
                        bufferedInputStream.read(tmp, 0, encryptLength);
                        byte[] decrypted = NativeBlowfish.decrypt(tmp, pw.getBytes());
                        bufferedOutputStream.write(decrypted);
                    }
                    bufferedOutputStream.flush();
                    File resultFile = new File(outputPath);
                    if (resultFile.exists()) {
                        if (!resultFile.delete()) {
                            throw new IOException("Cannot delete same name file");
                        }
                    }
                    if (!tempFile.renameTo(resultFile)) {
                        throw new IOException("Cannot rename file");
                    }
                    bufferedInputStream.close();
                    bufferedOutputStream.close();
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, "file://" + outputPath));
                } catch (NativeSecp256k1Util.AssertFailException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR));
                } catch (IOException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private void copyToClipBoard(String text) {
        Context context = this.cordova.getContext();
        this.cordova.getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("encrypted text", text);
                clipboard.setPrimaryClip(clip);
            }
        });
    }

    private void compressVideo(JSONArray args, CallbackContext callbackContext) throws Exception {
        String path = args.getString(0);
        int w = args.getInt(1);
        int h = args.getInt(2);
        String rootDir = args.getString(3);
        String destFileName = args.getString(4);
        rootDir = Uri.parse(rootDir).getPath();
        File rootDirFile = new File(rootDir);
        if (!rootDirFile.exists()) {
            if (!rootDirFile.mkdir())
                throw new IOException("Cannot create SecretTalk directory!");
        }
        String outputPath = rootDir + destFileName;
        path = Uri.parse(path).getPath();
        String cmd = "-y -i " + path + " -strict -2 -vcodec libx264 -preset ultrafast " +
                "-crf 24 -acodec aac -ar 44100 -ac 2 -b:a 128k -s " + w + "x" + h + " " + outputPath;
        if (getFFmpeg() == null) {
            callbackContext.error("ffmpeg not initialized!");
            return;
        }
        File inFile = new File(path);
        if (!inFile.exists()) {
            callbackContext.error("input file not exist!");
            return;
        }

        File mFile = new File(outputPath);
        if (mFile.exists()) {
            mFile.delete();
        }
        try {
            String[] cmds = cmd.split(" ");
            getFFmpeg().execute(cmds, new ExecuteBinaryResponseHandler() {
                @Override
                public void onFailure(String message) {
                    if (mFile.exists()) {
                        mFile.delete();
                    }
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, message));
                }

                @Override
                public void onSuccess(String message) {
                    JSONArray out = new JSONArray();
                    out.put("file://" + outputPath);
                    out.put(mFile.length());
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, out));
                }
            });
        } catch (FFmpegCommandAlreadyRunningException e) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
        }
    }

    private void compressAudio(JSONArray args, CallbackContext callbackContext) throws Exception {
        String path = args.getString(0);
        String rootDir = args.getString(1);
        String destFileName = args.getString(2);
        rootDir = Uri.parse(rootDir).getPath();
        File rootDirFile = new File(rootDir);
        if (!rootDirFile.exists()) {
            if (!rootDirFile.mkdir())
                throw new IOException("Cannot create SecretTalk directory!");
        }
        String outputPath = rootDir + destFileName;
        path = Uri.parse(path).getPath();
        String cmd = "-y -i " + path + " -ar 8000 -ac 1 " + outputPath;
        if (getFFmpeg() == null) {
            callbackContext.error("ffmpeg not initialized!");
            return;
        }
        File inFile = new File(path);
        if (!inFile.exists()) {
            callbackContext.error("input file not exist!");
            return;
        }

        if (!hasWritePermission()) {
            PermissionHelper.requestPermission(this, 0, Manifest.permission.WRITE_EXTERNAL_STORAGE);
            return;
        }

        File mFile = new File(outputPath);
        if (mFile.exists()) {
            mFile.delete();
        }
        try {
            String[] cmds = cmd.split(" ");
            getFFmpeg().execute(cmds, new ExecuteBinaryResponseHandler() {
                @Override
                public void onFailure(String message) {
                    if (mFile.exists()) {
                        mFile.delete();
                    }
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, message));
                }

                @Override
                public void onSuccess(String message) {
                    JSONArray out = new JSONArray();
                    out.put("file://" + outputPath);
                    out.put(mFile.length());
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, out));
                }
            });
        } catch (FFmpegCommandAlreadyRunningException e) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
        }
    }

    private void showExportView(JSONArray args, CallbackContext callbackContext) {
        AlertDialog.Builder builder = new AlertDialog.Builder(cordova.getActivity());
        LayoutInflater inflater = cordova.getActivity().getLayoutInflater();
        builder.setView(inflater.inflate(R.layout.export_main, null))
                .setPositiveButton(R.string.EXPORT_VIEW_CONFIRM, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int id) {
                    }
                })
                .setNegativeButton(R.string.EXPORT_VIEW_CANCEL, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                    }
                });
        AlertDialog dialog = builder.create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                EditText m_InputPW = dialog.findViewById(R.id.input_pw);
                EditText m_ConfirmPW =dialog.findViewById(R.id.input_pw2);
                if(m_InputPW.getText().length() <= 0 || m_ConfirmPW.getText().length() <= 0){
                    Toast.makeText(dialog.getContext(), R.string.EXPORT_VIEW_PLEASE_INPUT, Toast.LENGTH_SHORT).show();
                    return;
                }
                if(!m_InputPW.getText().toString().equals(m_ConfirmPW.getText().toString())){
                    Toast.makeText(dialog.getContext(), R.string.EXPORT_VIEW_CONFIRM_INPUT, Toast.LENGTH_SHORT).show();
                    return;
                }
                cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        try {
                            exportPrivateKey(m_InputPW.getText().toString(), args, callbackContext);
                        } catch (Exception e) {
                            callbackContext.error(e.getMessage());
                        }
                    }
                });
                dialog.dismiss();
            }
        });
    }

    private void downloadFile(JSONArray args, CallbackContext callbackContext) throws Exception {
        String url = args.getString(0);
        URL website = new URL(url);
        String rootDir = Environment.getExternalStorageDirectory().getPath() + "/" + DIRECTORY_NAME + "/";
        File rootDirFile = new File(rootDir);
        if (!rootDirFile.exists()) {
            if (!rootDirFile.mkdir())
                throw new IOException("Cannot create SecretTalk directory");
        }
        File tempFile = new File(rootDir, "download.temp");
        if (!tempFile.exists()) {
            if (!tempFile.createNewFile()) {
                throw new IOException("Cannot create temp file");
            }
        }
        ReadableByteChannel rbc = Channels.newChannel(website.openStream());
        FileOutputStream fos = new FileOutputStream(tempFile);
        long blockSize = 1048576;
        long position = 0;
        long count = 0;
        while ((count = fos.getChannel().transferFrom(rbc, position, blockSize)) > 0) {
            position += count;
        }
        String fileName = getFileNameFromURL(url);
        File resultFile = new File(rootDir, fileName);
        if (resultFile.exists()) {
            if (!resultFile.delete()) {
                throw new IOException("Cannot delete same name file");
            }
        }
        if (!tempFile.renameTo(resultFile)) {
            throw new IOException("Cannot rename file");
        }
        fos.close();
        JSONArray out = new JSONArray();
        out.put("file://" + rootDir + fileName);
        out.put(resultFile.length());
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, out));
    }

    private void combineFile(JSONArray args, CallbackContext callbackContext) throws Exception {
        String path = args.getString(0);
        String header = args.getString(1);
        String destFileName = args.getString(2);
        int base64Flag = args.getInt(3);
        byte[] headerBytes;
        if (base64Flag > 0) {
            headerBytes = header.getBytes();
        } else {
            headerBytes = Base64.decode(header);
        }
        FileUtils.getFilePlugin().TryReadFileByChunk(Uri.parse(path), args, callbackContext, new Filesystem.ReadFileCallback() {
            @Override
            public void handleData(InputStream inputStream, String contentType) {
                try {
                    String rootDir = Environment.getExternalStorageDirectory().getPath() + "/" + DIRECTORY_NAME + "/";
                    File rootDirFile = new File(rootDir);
                    if (!rootDirFile.exists()) {
                        if (!rootDirFile.mkdir())
                            throw new IOException("Cannot create SecretTalk directory");
                    }

                    File tempFile = new File(rootDir, "combine.temp");
                    if (!tempFile.exists()) {
                        if (!tempFile.createNewFile()) {
                            throw new IOException("Cannot create temp file");
                        }
                    }
                    final int BUFFER_SIZE = 1048576;
                    byte[] tmp = new byte[BUFFER_SIZE];
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(tempFile));
                    bufferedOutputStream.write(headerBytes);

                    BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                    while (bufferedInputStream.available() > 0) {
                        int count = bufferedInputStream.read(tmp, 0, BUFFER_SIZE);
                        bufferedOutputStream.write(tmp, 0, count);
                    }
                    bufferedOutputStream.flush();
                    String path = rootDir + destFileName;
                    File resultFile = new File(path);
                    if (resultFile.exists()) {
                        if (!resultFile.delete()) {
                            throw new IOException("Cannot delete same name file");
                        }
                    }
                    if (!tempFile.renameTo(resultFile)) {
                        throw new IOException("Cannot rename file");
                    }
                    bufferedInputStream.close();
                    bufferedOutputStream.close();
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, "file://" + path));
                } catch (IOException e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                } catch (Exception e) {
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.getMessage()));
                }
            }
        });
    }

    private void getAudioDuration(JSONArray args, CallbackContext callbackContext) throws Exception {
        String path = args.getString(0);
        File file = new File(Uri.parse(path).getPath());
        if (!file.exists())
            throw new IOException("audio file not exist!");
        MediaMetadataRetriever mmr = new MediaMetadataRetriever();
        mmr.setDataSource(file.getPath());
        String duration = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION);
        mmr.release();
        callbackContext.success(duration);
    }

    private void getCurrentLocale(JSONArray args, CallbackContext callbackContext) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Locale locale = cordova.getActivity().getResources().getConfiguration().getLocales().get(0);
            callbackContext.success(locale.getLanguage());
        } else {
            //noinspection deprecation
            Locale locale = cordova.getActivity().getResources().getConfiguration().locale;
            callbackContext.success(locale.getLanguage());
        }
    }

    private String getFileNameFromURL(String url) {
        if (url == null) {
            return "";
        }
        try {
            URL resource = new URL(url);
            String host = resource.getHost();
            if (host.length() > 0 && url.endsWith(host)) {
                // handle ...example.com
                return "";
            }
        } catch (MalformedURLException e) {
            return "";
        }

        int startIndex = url.lastIndexOf('/') + 1;
        int length = url.length();

        // find end index for ?
        int lastQMPos = url.lastIndexOf('?');
        if (lastQMPos == -1) {
            lastQMPos = length;
        }

        // find end index for #
        int lastHashPos = url.lastIndexOf('#');
        if (lastHashPos == -1) {
            lastHashPos = length;
        }

        // calculate the end index
        int endIndex = Math.min(lastQMPos, lastHashPos);
        return url.substring(startIndex, endIndex);
    }

    class UserInfo {
        public String Label;
        public String Host;
        public HashMap<Integer, Pair<byte[], byte[]>> KeyPairs;
    }

}