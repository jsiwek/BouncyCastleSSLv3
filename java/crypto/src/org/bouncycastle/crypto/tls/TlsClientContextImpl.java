package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

class TlsClientContextImpl implements TlsClientContext
{
    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;
    private TlsProtocolVersion clientVersion;
    private TlsProtocolVersion negotiatedVersion;

    private Object userObject = null;

    TlsClientContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters, TlsProtocolVersion clientVersion, TlsProtocolVersion negotiatedVersion)
    {
        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
        this.clientVersion = clientVersion;
        this.negotiatedVersion = negotiatedVersion;
    }

    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }

    public SecurityParameters getSecurityParameters()
    {
        return securityParameters;
    }

    public Object getUserObject()
    {
        return userObject;
    }

    public void setUserObject(Object userObject)
    {
        this.userObject = userObject;
    }

    public void writeClientVersion(byte[] buf, int offset) {
        buf[offset] = (byte) clientVersion.getMajorVersion();
        buf[offset + 1] = (byte) clientVersion.getMinorVersion();
    }

    public void setNegotiatedVersion(TlsProtocolVersion v) {
        this.negotiatedVersion = v;
    }

    public void writeVersion(OutputStream os) throws IOException {
        os.write(negotiatedVersion.getMajorVersion());
        os.write(negotiatedVersion.getMinorVersion());
    }

    public void writeVersion(byte[] buf, int offset) {
        buf[offset] = (byte) negotiatedVersion.getMajorVersion();
        buf[offset + 1] = (byte) negotiatedVersion.getMinorVersion();
    }

    public TlsProtocolVersion getNegotiatedVersion() {
        return negotiatedVersion;
    }
}
