package nl.mansoft.isoappletprovider;

import nl.mansoft.smartcardio.ResponseAPDU;

public interface TransmitCallback {
    void callBack(ResponseAPDU responseAPDU);
}
