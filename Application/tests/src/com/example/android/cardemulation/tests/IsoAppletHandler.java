package com.example.android.cardemulation.tests;

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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import nl.mansoft.openmobileapi.util.ResponseApdu;
import nl.mansoft.pkcs15.token.impl.IsoAppletToken;
import nl.mansoft.util.SmartcardIO;

public class IsoAppletHandler implements SEService.CallBack {
    public static final String TAG = IsoAppletHandler.class.getSimpleName();
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };
    private SmartcardIO mSmartcardIO;

    public IsoAppletHandler(Context context) {
        mSmartcardIO = new SmartcardIO();
        try {
            mSmartcardIO.setup(context, this);
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

    private void testCertificates(PKCS15Objects objs) {
        SequenceOf<PKCS15Certificate> certificates = objs.getCertificates();
        List<PKCS15Certificate> list = certificates.getSequence();
        for (PKCS15Certificate pkcs15certificate : list) {
            try {
                CommonObjectAttributes commonObjectAttributes = pkcs15certificate.getCommonObjectAttributes();
                String label = commonObjectAttributes.getLabel();
                Log.i(TAG, label);
                X509Certificate certificate = (X509Certificate) pkcs15certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate();
                Log.i(TAG, certificate.toString());
                Log.i(TAG, SmartcardIO.hex(getThumbprint(certificate)));
            } catch (CertificateParsingException ex) {
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void serviceConnected(SEService seService) {
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
                PKCS15Objects objs = PKCS15Objects.readInstance(token.readEFData(), new TokenContext(token));
                testCertificates(objs);
                mSmartcardIO.teardown();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            Log.e(TAG, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}