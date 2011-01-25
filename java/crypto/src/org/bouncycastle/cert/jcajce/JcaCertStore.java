package org.bouncycastle.cert.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;

public class JcaCertStore
    extends CollectionStore
{
    /**
     * Basic constructor.
     *
     * @param collection - initial contents for the store, this is copied.
     */
    public JcaCertStore(Collection collection)
        throws CertificateEncodingException
    {
        super(convertCerts(collection));
    }

    private static Collection convertCerts(Collection collection)
        throws CertificateEncodingException
    {
        List list = new ArrayList(collection.size());

        for (Iterator it = collection.iterator(); it.hasNext();)
        {
            Object o = it.next();

            if (o instanceof X509Certificate)
            {
                X509Certificate cert = (X509Certificate)o;

                list.add(new X509CertificateHolder(cert.getEncoded()));
            }
            else
            {
                list.add((X509CertificateHolder)o);
            }
        }

        return list;
    }
}
