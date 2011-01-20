package org.bouncycastle.cms;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.io.Streams;

public class CMSTypedStream
{
    private static final int BUF_SIZ = 32 * 1024;
    
    private final String      _oid;
    private final InputStream _in;

    public CMSTypedStream(
        InputStream in)
    {
        this(PKCSObjectIdentifiers.data.getId(), in, BUF_SIZ);
    }
    
    public CMSTypedStream(
         String oid,
         InputStream in)
    {
        this(oid, in, BUF_SIZ);
    }
    
    public CMSTypedStream(
        String      oid,
        InputStream in,
        int         bufSize)
    {
        _oid = oid;
        _in = new FullReaderStream(in, bufSize);
    }

    public String getContentType()
    {
        return _oid;
    }
    
    public InputStream getContentStream()
    {
        return _in;
    }

    public void drain() 
        throws IOException
    {
        Streams.drain(_in);
        _in.close();
    }

    private class FullReaderStream
        extends InputStream
    {
        InputStream _stream;
        
        FullReaderStream(
            InputStream in,
            int         bufSize)
        {
            _stream = new BufferedInputStream(in, bufSize);
        }
        
        public int read() 
            throws IOException
        {
            return _stream.read();
        }
        
        public int read(
            byte[] buf,
            int    off,
            int    len) 
            throws IOException
        {
            int    rd = 0;
            int    total = 0;
            
            while (len != 0 && (rd = _stream.read(buf, off, len)) > 0)
            {
                off += rd;
                len -= rd;
                total += rd;
            }
            
            if (total > 0)
            {
                return total;
            }
            else
            {
                return -1;
            }
        }
        
        public void close() 
            throws IOException
        {
            _stream.close();
        }
    }
}
