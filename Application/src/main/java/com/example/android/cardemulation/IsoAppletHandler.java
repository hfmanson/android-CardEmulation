package com.example.android.cardemulation;

import android.content.Context;

import com.example.android.common.logger.Log;

import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.impl.ApplicationFactoryImpl;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenPath;
import org.simalliance.openmobileapi.SEService;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import nl.mansoft.openmobileapi.util.ResponseApdu;
import nl.mansoft.pkcs15.token.impl.IsoAppletToken;
import nl.mansoft.util.SmartcardIO;

public class IsoAppletHandler implements SEService.CallBack {
    public static final String TAG = IsoAppletHandler.class.getSimpleName();
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };
    private SmartcardIO mSmartcardIO;
    private CardService mCardService;
    private PKCS15Objects mPKCS15Objects;
    private X509Certificate mKeyCertificate;
    private X509Certificate mCaCertificate;
    private int mLockCertificateCount;
    private X509Certificate[] mLockCertificates;
    public static final String KEYSTORE_FILENAME = "keystore";

    public IsoAppletHandler(Context context) {

        mSmartcardIO = new SmartcardIO();
        mLockCertificates = new X509Certificate[10];
        mLockCertificateCount = 0;
        try {
            mSmartcardIO.setup(context, this);
            mCardService = (CardService) context;
        } catch (IOException e) {
            e.printStackTrace();
        }
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
        return CardService.ConcatArrays(thumbprint, CardService.SELECT_OK_SW);
    }

    public void readCertificatesFromSimToKeystore(KeyStore ks) {
        try {
            mSmartcardIO.setSession();
            mSmartcardIO.openChannel(AID_ISOAPPLET);
            ResponseApdu resp = mSmartcardIO.login(new byte[] { 0x31, 0x32, 0x33, 0x34});
            final ApplicationFactoryImpl applicationFactory = new ApplicationFactoryImpl();

            Token token = new IsoAppletToken(mSmartcardIO);
            List<Application> apps = null;
            try {
                apps = applicationFactory.listApplications(token);
                Application app = apps.get(0);
                PathHelper.selectDF(token,new TokenPath(app.getApplicationTemplate().getPath()));
                token.selectEF(0x5031);
                mPKCS15Objects = PKCS15Objects.readInstance(token.readEFData(), new TokenContext(token));
                SequenceOf<PKCS15Certificate> certificates = mPKCS15Objects.getCertificates();
                List<PKCS15Certificate> list = certificates.getSequence();
                for (PKCS15Certificate pkcs15certificate  : list) {
                    try {
                        CommonObjectAttributes commonObjectAttributes = pkcs15certificate.getCommonObjectAttributes();
                        String label = commonObjectAttributes.getLabel();
                        Log.i(TAG, label);
                        X509Certificate certificate = (X509Certificate) pkcs15certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate();
                        Log.i(TAG, certificate.toString());
                        ks.setCertificateEntry(label, certificate);
                    } catch (CertificateParsingException ex) {
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            Log.e(TAG, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void printAliases(KeyStore ks) throws KeyStoreException {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Log.i(TAG, alias);
        }
    }

    @Override
    public void serviceConnected(SEService seService) {
        Log.i(TAG, "serviceConnected()");
        try {
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
            printAliases(ks);
            mKeyCertificate = (X509Certificate) ks.getCertificate("keycert");
            mCaCertificate = (X509Certificate) ks.getCertificate("CA");
            mCardService.sendResponseApdu(responseAPDU());
            //mLockCertificates[mLockCertificateCount++] = certificate;
            //byte[] thumbprint = getThumbprint(certificate);
            //Log.i(TAG, SmartcardIO.hex(thumbprint));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void teardown() {
        Log.i(TAG, "teardown()");
        mSmartcardIO.teardown();
    }
}
