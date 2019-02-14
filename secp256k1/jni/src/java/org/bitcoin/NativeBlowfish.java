package org.bitcoin;

import com.google.common.base.Preconditions;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static org.bitcoin.NativeSecp256k1Util.assertEquals;

public class NativeBlowfish {

    private static final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    private static final Lock r = rwl.readLock();
    private static final Lock w = rwl.writeLock();
    private static ThreadLocal<ByteBuffer> nativeECDSABuffer = new ThreadLocal<ByteBuffer>();

    public static byte[] encrypt(byte[] data, byte[] pw) throws NativeSecp256k1Util.AssertFailException {
        if(data.length <=0){
            throw new NativeSecp256k1Util.AssertFailException("FAIL: Bad decrypt data length!");
        }
        if(pw.length <=0){
            throw new NativeSecp256k1Util.AssertFailException("FAIL: Bad password length!");
        }
        Secp256k1Context.getContext();
        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < data.length + pw.length) {
            byteBuff = ByteBuffer.allocateDirect(data.length + pw.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(pw);
        byteBuff.put(data);
        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = blowfish_encrypt(byteBuff, pw.length, data.length);
        } finally {
            r.unlock();
        }

        byte[] pubArr = retByteArray[0];
        int pubLen = new BigInteger(new byte[] { retByteArray[1][0] }).intValue();
//        int retVal = new BigInteger(new byte[] { retByteArray[1][1] }).intValue();

        assertEquals(pubArr.length, pubLen, "Got bad encrypt length.");

//        return retVal == 0 ? new byte[0]: pubArr;
        return pubArr;
    }

    public static byte[] decrypt(byte[] data, byte[] pw) throws NativeSecp256k1Util.AssertFailException {
        if(data.length <=0){
            throw new NativeSecp256k1Util.AssertFailException("FAIL: Bad decrypt data length!");
        }
        if(pw.length <=0){
            throw new NativeSecp256k1Util.AssertFailException("FAIL: Bad password length!");
        }
        if(data.length >= 1024*1024*1024){
            throw new NativeSecp256k1Util.AssertFailException("FAIL: decrypt data length bigger than 1 GB!");
        }
        Secp256k1Context.getContext();
        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < data.length + pw.length) {
            byteBuff = ByteBuffer.allocateDirect(data.length + pw.length);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        byteBuff.rewind();
        byteBuff.put(pw);
        byteBuff.put(data);
        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = blowfish_decrypt(byteBuff,  pw.length, data.length);
        } finally {
            r.unlock();
        }

        byte[] pubArr = retByteArray[0];
        int pubLen = new BigInteger(new byte[] { retByteArray[1][0] }).intValue();
        int retVal = new BigInteger(new byte[] { retByteArray[1][1] }).intValue();

        assertEquals(pubArr.length, pubLen, "Got bad decrypt length.");

//        return retVal == 0 ? new byte[0]: pubArr;
        return pubArr;
    }

    private static native byte[][] blowfish_encrypt(ByteBuffer byteBuff, long keyLength, long dataLength);
    private static native byte[][] blowfish_decrypt(ByteBuffer byteBuff, long keyLength, long dataLength);
}
