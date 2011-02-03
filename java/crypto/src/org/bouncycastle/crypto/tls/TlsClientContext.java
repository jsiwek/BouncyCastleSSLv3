package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

public interface TlsClientContext
{
    SecureRandom getSecureRandom();

    SecurityParameters getSecurityParameters();

    Object getUserObject();

    void setUserObject(Object userObject);

    // The highest available version supported by client
    void writeClientVersion(byte[] buf, int offset);

    // The negotiated protocol version
    void writeVersion(OutputStream os) throws IOException;
    void writeVersion(byte[] buf, int offset);

    // The highest common version supported by both client and server
    void setNegotiatedVersion(TlsProtocolVersion v);

    TlsProtocolVersion getNegotiatedVersion();
}
