package org.bitcoin;

import android.net.Uri;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.file.FileUtils;
import org.apache.xerces.impl.dv.util.Base64;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import de.flexiprovider.common.ies.IESParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.ec.FlexiECProvider;
import de.flexiprovider.ec.keys.ECKeyFactory;
import de.flexiprovider.ec.keys.ECPrivateKey;
import de.flexiprovider.ec.keys.ECPrivateKeySpec;
import de.flexiprovider.ec.keys.ECPublicKey;
import de.flexiprovider.ec.keys.ECPublicKeySpec;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.CurveRegistry;

public class NativeSecp256k1Wrap extends CordovaPlugin {

    private static final String BLOWFISH = "Blowfish";

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("verify")) {
            byte[] data = transferJSArrayToArray(args.getJSONArray(0));
            byte[] signature = transferJSArrayToArray(args.getJSONArray(1));
            byte[] pub = transferJSArrayToArray(args.getJSONArray(2));
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        boolean result = NativeSecp256k1.verify(data, signature, pub);
                        callbackContext.success(result ? 1 : 0);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("verify_recoverable")) {
            byte[] data = Base64.decode(args.getString(0));
            final byte[] hashData = Sha256Hash.hash(data);
            byte[] rsignature = Base64.decode(args.getString(1));
            byte[] pub = Base64.decode(args.getString(2));
            //convert recoverable signature to normal signature
            final byte[] signature = Arrays.copyOfRange(rsignature, 0, rsignature.length - 1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        boolean result = NativeSecp256k1.verify(hashData, signature, pub);
                        callbackContext.success(result ? 1 : 0);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("randomize")) {
            byte[] seed = transferJSArrayToArray(args.getJSONArray(0));
            try {
                boolean result = NativeSecp256k1.randomize(seed);
                callbackContext.success(result ? 1 : 0);
            } catch (Exception e) {
                callbackContext.error(e.getMessage());
            }
            return true;
        } else if (action.equals("generateAddressForKey")) {
            byte[] pubkey = Base64.decode(args.getString(0));
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String address = generateAddressForKey(pubkey);
                        callbackContext.success(address);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("recoverPubkeyFromRsig")) {
            byte[] data = Sha256Hash.hash(Base64.decode(args.getString(0)));
            byte[] rsignature = Base64.decode(args.getString(1));
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] pubkey = NativeSecp256k1.recoverPubkeyFromRsig(data, rsignature);
                        callbackContext.success(new JSONArray(pubkey));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("simpleEncrypt")) {
            String seed = args.getString(0);
            String toEncrypt = args.getString(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String encrypted = cSimpleEncrypt(seed, toEncrypt);
                        callbackContext.success(encrypted);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("simpleDecrypt")) {
            String seed = args.getString(0);
            String toDecrypt = args.getString(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String decrypted = cSimpleDecrypt(seed, toDecrypt);
                        callbackContext.success(decrypted);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("decryptDataBySimpleFile")) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        decryptDataBySimpleFile(args, callbackContext);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        return false;
    }

    private byte[] transferJSArrayToArray(JSONArray jsonArray) throws JSONException {
        if (jsonArray == null) return null;
        byte[] bytes = new byte[jsonArray.length()];
        for (int i = 0; i < jsonArray.length(); i++) {
            bytes[i] = (byte) ((int) jsonArray.get(i));
        }
        return bytes;
    }

    private byte[] encryptData(byte[] pubkey, byte[] data) throws Exception {
        Security.addProvider(new FlexiCoreProvider());
        Security.addProvider(new FlexiECProvider());
        CurveParams ecParams = new CurveRegistry.Secp256k1();
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubkey, ecParams);
        ECKeyFactory kf = new ECKeyFactory();
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

        Cipher cipher = Cipher.getInstance("ECIES", "FlexiEC");
        IESParameterSpec iesParams = new IESParameterSpec("AES128_CBC", "HmacSHA1", null, null);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, iesParams);
        return cipher.doFinal(data);
    }

    private byte[] decryptData(byte[] seckey, byte[] cipherBytes) throws Exception {
        Security.addProvider(new FlexiCoreProvider());
        Security.addProvider(new FlexiECProvider());

        CurveParams ecParams = new CurveRegistry.Secp256k1();
        ECKeyFactory kf = new ECKeyFactory();
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(new FlexiBigInt(1, seckey), ecParams);
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateSpec);

        Cipher cipher = Cipher.getInstance("ECIES", "FlexiEC");
        IESParameterSpec iesParams = new IESParameterSpec("AES128_CBC", "HmacSHA1", null, null);

        cipher.init(Cipher.DECRYPT_MODE, privateKey, iesParams);
        return cipher.doFinal(cipherBytes);
    }

    private String generateAddressForKey(byte[] pubkey) throws Exception {
        byte[] bytes = Utils.sha256hash160(pubkey);
        return Base58.encodeChecked(5, bytes);
    }

    private String simpleEncrypt(String seed, String value) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(seed.getBytes(), BLOWFISH);
        Cipher cipher = Cipher.getInstance(BLOWFISH);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.encode(encrypted);
    }

    private String simpleDecrypt(String seed, String encrypted) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(seed.getBytes(), BLOWFISH);
        Cipher cipher = Cipher.getInstance(BLOWFISH);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decrypted = cipher.doFinal(Base64.decode(encrypted));
        return new String(decrypted);
    }

    private String cSimpleEncrypt(String seed, String value) throws Exception {
        byte[] encrypted = NativeBlowfish.encrypt(value.getBytes(), seed.getBytes());
        return Base64.encode(encrypted);
    }

    private String cSimpleDecrypt(String seed, String encrypted) throws Exception {
        byte[] decrypted = NativeBlowfish.decrypt(Base64.decode(encrypted), seed.getBytes());
        return new String(decrypted);
    }

    private void decryptDataBySimpleFile(JSONArray args, CallbackContext callbackContext) throws Exception {
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
        FileUtils.getFilePlugin().TryReadFile(uri, args, callbackContext, new ReadFileCallback() {
            @Override
            public void handleData(byte[] content) {
                try {
                    File tempFile = new File(rootDirFile, "DecryptFile.temp");
                    if (!tempFile.exists()) {
                        if (!tempFile.createNewFile()) {
                            throw new IOException("Cannot create temp file");
                        }
                    }
                    String result = new String(content);
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(tempFile));
                    String decrypted = cSimpleDecrypt(pw, result);
                    String base64Image = decrypted.split(",")[1];
                    byte[] imageBytes = Base64.decode(base64Image);
                    bufferedOutputStream.write(imageBytes);
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

    public interface ReadFileCallback {
        public void handleData(byte[] content);
    }
}
