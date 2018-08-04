/*
* Copyright 2013 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


package com.example.android.cardemulation;

import android.os.Bundle;
import android.support.v4.app.FragmentTransaction;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ViewAnimator;

import com.example.android.common.activities.SampleActivityBase;
import com.example.android.common.logger.Log;
import com.example.android.common.logger.LogFragment;
import com.example.android.common.logger.LogWrapper;
import com.example.android.common.logger.MessageOnlyLogFilter;

import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.impl.ApplicationFactoryImpl;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenPath;
import org.simalliance.openmobileapi.SEService;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.List;

import nl.mansoft.openmobileapi.util.ResponseApdu;
import nl.mansoft.pkcs15.token.impl.IsoAppletToken;
import nl.mansoft.util.SmartcardIO;

/**
 * A simple launcher activity containing a summary sample description, sample log and a custom
 * {@link android.support.v4.app.Fragment} which can display a view.
 * <p>
 * For devices with displays with a width of 720dp or greater, the sample log is always visible,
 * on other devices it's visibility is controlled by an item on the Action Bar.
 */
public class MainActivity extends SampleActivityBase {

    public static final String TAG = "MainActivity";
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };

    private class Callback implements SEService.CallBack {
        //@Override
        public void serviceConnected(SEService seService) {
            try {
                mSmartcardIO.setSession();
                mSmartcardIO.openChannel(AID_ISOAPPLET);
                ResponseApdu resp = mSmartcardIO.login(new byte[] { 0x31, 0x32, 0x33, 0x34});
                onReady();
            } catch (IOException e) {
                Log.e(TAG, e.getMessage());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    // Whether the Log Fragment is currently shown
    private boolean mLogShown;
    private SmartcardIO mSmartcardIO;

    private void testCertificates(PKCS15Objects objs) {
        SequenceOf<PKCS15Certificate> cerficates = objs.getCertificates();
        List<PKCS15Certificate> list = cerficates.getSequence();
        for (PKCS15Certificate pkcs15certificate : list) {
            try {
                Certificate certificate = pkcs15certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate();
                Log.i(TAG, certificate.toString());
            } catch (CertificateParsingException ex) {
            }
        }
    }

    private void onReady() {
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
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mSmartcardIO = new SmartcardIO();
        try {
            mSmartcardIO.setup(this, new Callback());
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (savedInstanceState == null) {
            FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
            CardEmulationFragment fragment = new CardEmulationFragment();
            transaction.replace(R.id.sample_content_fragment, fragment);
            transaction.commit();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem logToggle = menu.findItem(R.id.menu_toggle_log);
        logToggle.setVisible(findViewById(R.id.sample_output) instanceof ViewAnimator);
        logToggle.setTitle(mLogShown ? R.string.sample_hide_log : R.string.sample_show_log);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch(item.getItemId()) {
            case R.id.menu_toggle_log:
                mLogShown = !mLogShown;
                ViewAnimator output = (ViewAnimator) findViewById(R.id.sample_output);
                if (mLogShown) {
                    output.setDisplayedChild(1);
                } else {
                    output.setDisplayedChild(0);
                }
                supportInvalidateOptionsMenu();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /** Create a chain of targets that will receive log data */
    @Override
    public void initializeLogging() {
        // Wraps Android's native log framework.
        LogWrapper logWrapper = new LogWrapper();
        // Using Log, front-end to the logging chain, emulates android.util.log method signatures.
        Log.setLogNode(logWrapper);

        // Filter strips out everything except the message text.
        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        // On screen logging via a fragment with a TextView.
        LogFragment logFragment = (LogFragment) getSupportFragmentManager()
                .findFragmentById(R.id.log_fragment);
        msgFilter.setNext(logFragment.getLogView());

        Log.i(TAG, "Ready");
    }
}
