package org.bouncycastle.crypto.tls;

public enum TlsProtocolVersion {
    SSLv3(0x300),
    TLSv10(0x301),
    TLSv11(0x302),
    TLSv12(0x303);

    int version;

    private TlsProtocolVersion(int v) {
        version = v;
    }

    public int getVersion() {
        return version;
    }

    public int getMajorVersion() {
        return version >> 8;
    }

    public int getMinorVersion() {
        return version & 0xff;
    }

    public static TlsProtocolVersion get(String name) throws TlsFatalAlert {
        if ("SSLv3".equals(name)) return SSLv3;
        else if ("TLSv1".equals(name)) return TLSv10;
        else if ("TLSv10".equals(name)) return TLSv10;
        else if ("TLSv11".equals(name)) return TLSv11;
        else if ("TLSv12".equals(name)) return TLSv12;
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    public static TlsProtocolVersion get(int major, int minor)
            throws TlsFatalAlert {
        for (TlsProtocolVersion p : TlsProtocolVersion.values()) {
            if (p.getMajorVersion() == major && p.getMinorVersion() == minor) {
                return p;
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }
}
