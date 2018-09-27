package nl.mansoft.isoappletprovider;

import android.content.Context;
import android.util.Log;

import org.opensc.pkcs15.token.Token;

import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.Reader;
import org.simalliance.openmobileapi.SEService;
import org.simalliance.openmobileapi.Session;

import java.io.IOException;

import nl.mansoft.smartcardio.CardException;
import nl.mansoft.smartcardio.CommandAPDU;
import nl.mansoft.smartcardio.ResponseAPDU;

public class SmartcardIO {
    private final static String TAG = SmartcardIO.class.getSimpleName();
    public final static byte[] AID_ISOAPPLET = { (byte) 0xF2, (byte) 0x76, (byte) 0xA2, (byte) 0x88, (byte) 0xBC, (byte) 0xFB, (byte) 0xA6, (byte) 0x9D, (byte) 0x34, (byte) 0xF3, (byte) 0x10, (byte) 0x01 };
    // File system related INS:
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_CREATE_FILE = (byte) 0xE0;
    public static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_DELETE_FILE = (byte) 0xE4;
    // Other INS:
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x46;
    public static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_PUT_DATA = (byte) 0xDB;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final int SW_NO_ERROR = 0x9000;

    public boolean debug = false;
    private Token token;
    private static SmartcardIO smartcardIO;


    private Session session;
    private Channel cardChannel;
    private SEService mSeService;
    private Reader mReader;

    public void setupToken() {
        token = new IsoAppletToken(this);
    }

    public Token getToken() {
        return token;
    }

    public static SmartcardIO getInstance() {
        if (smartcardIO == null) {
                smartcardIO = new SmartcardIO();
        }
        return smartcardIO;
    }

    public void showCommandApduInfo(CommandAPDU commandAPDU) {
            String msg = "command: CLA: " + Util.hex2(commandAPDU.getCLA()) + ", INS: " + Util.hex2(commandAPDU.getINS()) + ", P1: " + Util.hex2(commandAPDU.getP1()) + ", P2: " + Util.hex2(commandAPDU.getP2());
            int nc = commandAPDU.getNc();
            if (nc > 0) {
                msg += ", Nc: " + Util.hex2(nc) + ", data: " + Util.ByteArrayToHexString(commandAPDU.getData());
            }
            Log.d(TAG, msg + ", Ne: " + Util.hex2(commandAPDU.getNe()));
    }

    public void showResponseApduInfo(ResponseAPDU responseAPDU) {
        int status = responseAPDU.getSW();
        if (status == SW_NO_ERROR) {
            byte[] data = responseAPDU.getData();
            Log.d(TAG, "answer: " + responseAPDU.toString() + ", data: " + Util.ByteArrayToHexString(data));
        } else {
            Log.e(TAG, "ERROR: status: " + String.format("%04X", status));
        }
    }

    public ResponseAPDU runAPDU(CommandAPDU c) throws CardException {
        try {
            showCommandApduInfo(c);
            byte[] result = cardChannel.transmit(c.getBytes());
            ResponseAPDU responseAPDU = new ResponseAPDU(result);
            showResponseApduInfo(responseAPDU);
            return responseAPDU;
        } catch (IOException ex) {
            throw new CardException(ex.getMessage());
        }
    }

    public void runAPDU(final CommandAPDU c, final TransmitCallback callback) throws CardException {
        final byte[] bytes = c.getBytes();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] result = cardChannel.transmit(bytes);
                    ResponseAPDU responseAPDU = new ResponseAPDU(result);
                    showResponseApduInfo(responseAPDU);
                    callback.callBack(responseAPDU);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
    }

    public void setup(Context context, SEService.CallBack callBack) throws IOException {
        mSeService = new SEService(context, callBack);
    }

    public void getFirstReader() {
        if (mReader == null) {
            Log.d(TAG, "Retrieve available readers...");
            Reader[] readers = mSeService.getReaders();
            if (readers.length < 1) {
                Log.e(TAG, "No readers found");
            } else {
                mReader = readers[0];
            }
        }
    }

    public void teardown() {
        closeChannel();

        getFirstReader();
        if (mReader != null) {
            Log.d(TAG, "Closing Sessions from the first reader");
            mReader.closeSessions();
            mReader = null;
        }
        if (mSeService != null && mSeService.isConnected()) {
            Log.d(TAG, "Shutting down service");
            mSeService.shutdown();
            mSeService = null;
        }
    }

    public void closeChannel() {
        if (cardChannel != null) {
            cardChannel.close();
            cardChannel = null;
        }
    }

    public byte[] openChannel(byte aid[]) throws Exception {
        closeChannel();
        cardChannel = session.openLogicalChannel(aid);
        return cardChannel.getSelectResponse();
    }

    public static String hex2(int hex) {
        return String.format("%02X", hex & 0xff);
    }

    public static String hex(byte[] barr) {
        String result;
        if (barr == null) {
            result = "null";
        } else {
            result = "";
            for (byte b : barr) {
                result += " " + hex2(b);
            }
        }
        return result;
    }

    public void setSession() throws IOException {
        Log.d(TAG, "setSession()");
        getFirstReader();
        if (mReader != null) {
            Log.d(TAG, "Create Session from the first reader");
            session = mReader.openSession();
        }
    }

    public boolean verify(byte[] password) {
        boolean result = false;
        try {
            ResponseAPDU responseAPDU = runAPDU(new CommandAPDU(0x00, INS_VERIFY, 0x00, 0x01, password));
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                result = true;
            }
        } catch (CardException ex) {
        }
        return result;
    }

    public byte[] getChallenge(int numBytes) {
        byte[] data = null;
        try {
            ResponseAPDU responseAPDU = runAPDU(new CommandAPDU(0x00, INS_GET_CHALLENGE, 0x00, 0x00, numBytes));
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                data = responseAPDU.getData();
            }
        } catch (CardException ex) {
        }
        return data;
    }

    public boolean manageSecurityEnvironment(byte keyReference) {
        boolean result = false;
        try {
            CommandAPDU commandApdu = new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, 0xb6, new byte[]{(byte) 0x80, (byte) 0x01, (byte) 0x11, (byte) 0x81, (byte) 0x02, (byte) 0x50, (byte) 0x15, (byte) 0x84, (byte) 0x01, keyReference});
            ResponseAPDU responseApdu = smartcardIO.runAPDU(commandApdu);
            result = responseApdu.getSW() == SW_NO_ERROR;
        } catch (CardException ex) {
        }
        return result;
    }

    /**
     * decipher
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
     */
    public byte[] decipher(byte[] input, int inputOffset, int inputLen) {
        byte[] data = new byte[inputLen + 1];
        data[0] = 0; // padding indicator byte: "No further indication"
        System.arraycopy(input, inputOffset, data, 1, inputLen);
        byte[] decrypted = null;
        try {
            CommandAPDU commandApdu = new CommandAPDU(0x10, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data, 0, 0x80);
            ResponseAPDU responseApdu = runAPDU(commandApdu);
            if (responseApdu.getSW() == SW_NO_ERROR) {
                commandApdu = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data, 0x80, data.length - 0x80, 0x100);
                responseApdu = runAPDU(commandApdu);
                if (responseApdu.getSW() == SW_NO_ERROR) {
                    decrypted = responseApdu.getData();
                }
            }
        } catch (CardException ex) {
        }
        return decrypted;
    }

    /**
     * sign
     * @param input
     * @param inputLen
     * @return
     */
    public byte[] sign(byte[] input, int inputLen) {
        byte[] signature = null;
        try {
            CommandAPDU commandAPDU = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, input, 0, inputLen, 0x100);
            System.out.println("challenge: " + Util.ByteArrayToHexString(commandAPDU.getData()));
            ResponseAPDU responseAPDU = runAPDU(commandAPDU);
            if (responseAPDU.getSW() == SW_NO_ERROR) {
                signature = responseAPDU.getData();
            }
        } catch (CardException ex) {
        }
        return signature;
    }


}
