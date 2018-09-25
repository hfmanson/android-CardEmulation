/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.cardemulation;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import com.example.android.common.logger.Log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

import nl.mansoft.smartcardio.CardException;

/**
 * This is a sample APDU Service which demonstrates how to interface with the card emulation support
 * added in Android 4.4, KitKat.
 *
 * <p>This sample replies to any requests sent with the string "Hello World". In real-world
 * situations, you would need to modify this code to implement your desired communication
 * protocol.
 *
 * <p>This sample will be invoked for any terminals selecting AIDs of 0xF11111111, 0xF22222222, or
 * 0xF33333333. See src/main/res/xml/aid_list.xml for more details.
 *
 * <p class="note">Note: This is a low-level interface. Unlike the NdefMessage many developers
 * are familiar with for implementing Android Beam in apps, card emulation only provides a
 * byte-array based communication channel. It is left to developers to implement higher level
 * protocol support as needed.
 */
public class CardService extends HostApduService {
    private static final String TAG = "CardService";
    // AID for our loyalty card service.
    private static final String SAMPLE_LOYALTY_CARD_AID = "F222222222";
    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    public static final byte[] SW_NO_ERROR = new byte[] { (byte) 0x90, 0x00 };// ETSI TS 102 221 10.2.1.1: Normal ending of the command
    public static final byte[] SW_UNKNOWN_CLA = new byte[] { 0x6E, 0x00 }; // ETSI TS 102 221 10.2.1.5: Class not supported
    public static final byte[] SW_UNKNOWN_INS = new byte[] { 0x6D, 0x00 }; // ETSI TS 102 221 10.2.1.5: Instruction code not supported or invalid
    public static final byte[] SW_WRONG_LENGTH = new byte[] { 0x67, 0x00 }; // ETSI TS 102 221 10.2.1.5: Wrong length
    private static final byte[] SELECT_APDU = BuildSelectApdu(SAMPLE_LOYALTY_CARD_AID);
    private static final int CLA_CHAINING_MASK = 0x10;
    private IsoAppletHandler mIsoAppletHandler;
    private byte[] mSignature;
    private int mResponseLength;
    private ApduResponse mApduResponse;
    private byte[] mPayload;
    private int mPayloadOffset;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate()");
        mPayload = new byte[1024];
        mPayloadOffset = 0;
    }
    /**
     * Called if the connection to the NFC card is lost, in order to let the application know the
     * cause for the disconnection (either a lost link, or another AID being selected by the
     * reader).
     *
     * @param reason Either DEACTIVATION_LINK_LOSS or DEACTIVATION_DESELECTED
     */
    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "onDeactivated(" + reason + ")");
        if (mIsoAppletHandler != null) {
            mIsoAppletHandler.teardown();
            mIsoAppletHandler = null;
        }
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy()");
        super.onDestroy();
    }

    public void sendResponse(byte[] sw, byte[] data) {
        if (data == null) {
            sendResponseApdu(sw);
        } else {
            byte[] response = data;
            sendResponseApdu(ConcatArrays(response, sw));
        }
    }
    /**
     * This method will be called when a command APDU has been received from a remote device. A
     * response APDU can be provided directly by returning a byte-array in this method. In general
     * response APDUs must be sent as quickly as possible, given the fact that the user is likely
     * holding his device over an NFC reader when this method is called.
     *
     * <p class="note">If there are multiple services that have registered for the same AIDs in
     * their meta-data entry, you will only get called if the user has explicitly selected your
     * service, either as a default or just for the next tap.
     *
     * <p class="note">This method is running on the main thread of your application. If you
     * cannot return a response APDU immediately, return null and use the {@link
     * #sendResponseApdu(byte[])} method later.
     *
     * @param commandApdu The APDU that received from the remote device
     * @param extras A bundle containing extra data. May be null.
     * @return a byte-array containing the response APDU, or null if no response APDU can be sent
     * at this point.
     */
    // BEGIN_INCLUDE(processCommandApdu)
    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        byte[] response = null;
        Log.i(TAG, "Received APDU: " + ByteArrayToHexString(commandApdu));
        // If the APDU matches the SELECT AID command for this service,
        // send the loyalty card account number, followed by a SELECT_OK status trailer (0x9000).
        if (Arrays.equals(SELECT_APDU, commandApdu)) {
            String account = AccountStorage.GetAccount(this);
            byte[] accountBytes = account.getBytes();
            Log.i(TAG, "Sending account number: " + account);
            response = ConcatArrays(accountBytes, SW_NO_ERROR);
        } else if ((commandApdu[0] & ~CLA_CHAINING_MASK) == (byte) 0x00) { // CLA
            int ins = commandApdu[1] & 0xff;
            int dataLength = commandApdu[4] & 0xff;
            if (dataLength <= commandApdu.length - 5) {
                if (ins == 0x55 || ins == 0x56) {
                        System.arraycopy(commandApdu, 5, mPayload, mPayloadOffset, dataLength);
                        mPayloadOffset += dataLength;
                }
                if ((commandApdu[0] & CLA_CHAINING_MASK) == (byte) 0x00) {
                    switch (ins) {
                        case 0x55:
                            if (mIsoAppletHandler == null) {
                                byte[] fingerprint = new byte[mPayloadOffset];
                                System.arraycopy(mPayload, 0, fingerprint, 0, mPayloadOffset);
                                mIsoAppletHandler = new IsoAppletHandler(this, fingerprint);
                            } else {
                                Log.e(TAG, "Never reached??");
                            }
                            mPayloadOffset = 0;
                            break;
                        case 0x56:
                            if (mIsoAppletHandler != null) {
                                try {
                                    byte[] challenge = new byte[128];
                                    System.arraycopy(mPayload, 0, challenge, 0, 128);
                                    Log.i(TAG, "challenge: " + ByteArrayToHexString(challenge));
                                    int slotSignatureLength = mPayloadOffset - 128;
                                    byte[] slotSignature = new byte[slotSignatureLength];
                                    System.arraycopy(mPayload, 128, slotSignature, 0, slotSignatureLength);
                                    Log.i(TAG, "slot signature: " + ByteArrayToHexString(slotSignature));
                                    boolean slotSignatureOK = mIsoAppletHandler.verify(slotSignature);
                                    Log.i(TAG, "slot signature " + (slotSignatureOK ? "OK" : "INVALID"));
                                    mSignature = mIsoAppletHandler.sign(challenge);
                                    int responseLength = commandApdu[5 + dataLength] & 0xFF;
                                    if (responseLength == 0) {
                                        responseLength = mSignature.length;
                                        if (responseLength > 0x100) {
                                            responseLength = 0x100;
                                        }
                                    }
                                    Log.i(TAG, "responseLength: " + responseLength);
                                    mResponseLength = responseLength;
                                    Log.i(TAG, "signature: " + ByteArrayToHexString(mSignature));
                                    mApduResponse = new ApduResponse(mSignature, responseLength);
                                    //response = ConcatArrays(Arrays.copyOf(mSignature, responseLength), new byte[] { 0x61,(byte) (0x100 - mResponseLength) });
                                    response = mApduResponse.getResponse();
                                } catch (CardException e) {
                                    e.printStackTrace();
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                } catch (SignatureException e) {
                                    e.printStackTrace();
                                } catch (InvalidKeyException e) {
                                    e.printStackTrace();
                                }
                            } else {
                                Log.e(TAG, "mIsoAppletHandler is null");
                                response = SW_UNKNOWN_INS;
                            }
                            mPayloadOffset = 0;
                            break;
                        case 0xc0:
                            //response = ConcatArrays(Arrays.copyOfRange(mSignature, mResponseLength, 0x100), CardService.SW_NO_ERROR);
                            response = mApduResponse.getResponse();
                            mPayloadOffset = 0;
                            break;
                        default:
                            response = SW_UNKNOWN_INS;
                            break;
                    }

                } else {
                    response = SW_NO_ERROR;
                }
            } else {
                Log.e(TAG, "Wrong length");
                response = SW_WRONG_LENGTH;
            }
        } else {
            response = SW_UNKNOWN_CLA;
        }
        Log.i(TAG, "response: " +  (response == null ? "(null)" : ByteArrayToHexString(response)));
        return response;
    }
    // END_INCLUDE(processCommandApdu)

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X",
                aid.length() / 2) + aid);
    }

    /**
     * Utility method to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }

    /**
     * Utility method to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     * @throws java.lang.IllegalArgumentException if input length is incorrect
     */
    public static byte[] HexStringToByteArray(String s) throws IllegalArgumentException {
        int len = s.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Utility method to concatenate two byte arrays.
     * @param first First array
     * @param rest Any remaining arrays
     * @return Concatenated copy of input arrays
     */
    public static byte[] ConcatArrays(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
}
