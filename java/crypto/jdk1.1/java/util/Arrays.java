package java.util;

public class Arrays
{

    private Arrays() {}
    
    public static boolean equals(byte[] a, byte[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }
    public static List asList(Object[] a) {
    return new ArrayList(a);
    }

    private static class ArrayList extends AbstractList implements java.io.Serializable
    {
    private Object[] a;

    ArrayList(Object[] array)
    {
        a = array;
    }

    public int size()
    {
        return a.length;
    }

    public Object[] toArray()
    {
        return (Object[]) a.clone();
    }

    public Object get(int index)
    {
        return a[index];
    }

    public Object set(int index, Object element)
    {
        Object oldValue = a[index];
        a[index] = element;
        return oldValue;
    }

        public int indexOf(Object o)
    {
            if (o==null)
        {
                for (int i=0; i<a.length; i++)
                    if (a[i]==null)
                        return i;
            }
        else
        {
                for (int i=0; i<a.length; i++)
                    if (o.equals(a[i]))
                        return i;
            }
            return -1;
        }

        public boolean contains(Object o)
    {
            return indexOf(o) != -1;
        }
    }
}
