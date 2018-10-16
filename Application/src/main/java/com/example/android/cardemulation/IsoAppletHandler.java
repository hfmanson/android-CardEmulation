package com.example.android.cardemulation;

import android.content.Context;

import com.example.android.common.logger.Log;

import org.simalliance.openmobileapi.SEService;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import nl.mansoft.isoappletprovider.SimProvider;
import nl.mansoft.isoappletprovider.SmartcardIO;
import nl.mansoft.smartcardio.CardException;

public class IsoAppletHandler implements SEService.CallBack {
    public static final String TAG = IsoAppletHandler.class.getSimpleName();
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };
    private SmartcardIO mSmartcardIO;
    private CardService mCardService;
    private X509Certificate mKeyCertificate;
    private X509Certificate mCaCertificate;
    private int mLockCertificateCount;
    private X509Certificate[] mLockCertificates;
    private X509Certificate mLockCertificate;
    private byte[] mLockFingerprint;
    private byte[] mRandom;
    private Provider mProvider;
    private KeyStore mKeystore;

    public static final String KEYSTORE_FILENAME = "keystore";

    public IsoAppletHandler(Context context, byte[] lockFingerprint) {
        mLockFingerprint = lockFingerprint;
        Log.i(TAG, "lock fingerprint: " + CardService.ByteArrayToHexString(lockFingerprint));
        mSmartcardIO = new SmartcardIO(context, AID_ISOAPPLET, this);
        mSmartcardIO.mDebug = true;
        mLockCertificates = new X509Certificate[10];
        mLockCertificateCount = 0;
        mCardService = (CardService) context;
    }

    public static byte[] getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        return md.digest();
    }

    public byte[] responseAPDU() throws CertificateEncodingException, NoSuchAlgorithmException {
        Log.i(TAG, "responseAPDU()");
        byte[] thumbprint = getThumbprint(mKeyCertificate);
        Log.i(TAG, SmartcardIO.hex(thumbprint));
        SecureRandom secureRandom = new SecureRandom();
        mRandom = new byte[128];
        secureRandom.nextBytes(mRandom);
        Log.i(TAG, "random bytes: " + CardService.ByteArrayToHexString(mRandom));
        byte[] data = CardService.ConcatArrays(thumbprint, mRandom);
        Log.i(TAG, "data length: " + data.length);
        return data;
    }

    public void readCertificatesFromSimToKeystore(KeyStore ks) throws KeyStoreException {
        Enumeration<String> aliases = mKeystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Log.i(TAG,"alias: " + alias);
            Certificate certificate = mKeystore.getCertificate(alias);
            ks.setCertificateEntry(alias, certificate);
        }
    }

    public static void printAliases(KeyStore ks) throws KeyStoreException {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Log.i(TAG, alias);
        }
    }

    public byte[] sign(byte[] challenge) throws CardException {
        byte[] signature = null;
        try {
            PrivateKey privatekey = (PrivateKey) mKeystore.getKey("keycert", null);
            Signature signSignature = Signature.getInstance("NONEwithRSA", mProvider);
            signSignature.initSign(privatekey);
            signSignature.update(challenge);
            signature = signSignature.sign();

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return signature;
    }

    public boolean verify(byte[] slotSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(mLockCertificate);
        sig.update(mRandom);
        return sig.verify(slotSignature);
    }

    public byte[] encrypt(byte[] data) {
        byte[] encrypted = null;
        try {
            PublicKey pubkey = mLockCertificate.getPublicKey();
            Cipher cipher = Cipher.getInstance(pubkey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            encrypted = cipher.doFinal(data);
            Log.d(TAG, "encrypted length: " + encrypted.length);
            Log.d(TAG,"encrypted: " + CardService.ByteArrayToHexString(encrypted));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    @Override
    public void serviceConnected(SEService seService) {
        Log.i(TAG, "serviceConnected()");
        try {
            mSmartcardIO.setSessionAndOpenChannel();
            mProvider = new SimProvider();
            Security.addProvider(mProvider);
            mKeystore = KeyStore.getInstance("SIM");
            mKeystore.load(null, new char[] { '1', '2', '3', '4' });

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try {
                FileInputStream fis = mCardService.openFileInput(KEYSTORE_FILENAME);
                Log.i(TAG, "reading keystore file");
                ks.load(fis, null);
                fis.close();
            } catch (FileNotFoundException ex) {
                Log.i(TAG, "creating keystore file");
                FileOutputStream fos = mCardService.openFileOutput(KEYSTORE_FILENAME, Context.MODE_PRIVATE);
                ks.load(null);
                readCertificatesFromSimToKeystore(ks);
                ks.store(fos, null);
                fos.close();
            }
            //printAliases(ks);
            mKeyCertificate = (X509Certificate) ks.getCertificate("keycert");
            Log.i(TAG, mKeyCertificate.toString());
            mCaCertificate = (X509Certificate) ks.getCertificate("CA");
            mLockCertificate = (X509Certificate) ks.getCertificate("slot1");
            if (Arrays.equals(getThumbprint(mLockCertificate), mLockFingerprint)) {
                Log.i(TAG, "Lock certificate fingerprint match OK");
                byte[] data = responseAPDU();
                encrypt(data);
                mCardService.sendResponse(CardService.SW_NO_ERROR, data);
            } else {
                Log.i(TAG, "Lock certificate fingerprint does not match");
                mCardService.sendResponse(new byte[] { 0x69, (byte) 0x82 }, null);
            }
            //signTest();
            //mLockCertificates[mLockCertificateCount++] = certificate;
            //byte[] thumbprint = getThumbprint(certificate);
            //Log.i(TAG, SmartcardIO.hex(thumbprint));
        } catch (Exception e) {
            Log.e(TAG, e.getMessage());
            mCardService.sendResponse(new byte[] { 0x6F, (byte) 0x00 }, null);
            //e.printStackTrace();
        }
    }

    public void teardown() {
        Log.i(TAG, "teardown()");
        mSmartcardIO.teardown();
        mSmartcardIO = null;
    }
}
