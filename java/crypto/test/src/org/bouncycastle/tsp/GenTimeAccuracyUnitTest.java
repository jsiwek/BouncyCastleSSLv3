package org.bouncycastle.tsp;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.tsp.Accuracy;

public class GenTimeAccuracyUnitTest
    extends TestCase
{
    private static final DERInteger ZERO_VALUE = new DERInteger(0);
    private static final DERInteger ONE_VALUE = new DERInteger(1);
    private static final DERInteger TWO_VALUE = new DERInteger(2);
    private static final DERInteger THREE_VALUE = new DERInteger(3);

    public void testOneTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, TWO_VALUE, THREE_VALUE));
        
        checkValues(accuracy, ONE_VALUE, TWO_VALUE, THREE_VALUE);
        
        checkToString(accuracy, "1.002003");
    }

    public void testThreeTwoOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, ONE_VALUE));
        
        checkValues(accuracy, THREE_VALUE, TWO_VALUE, ONE_VALUE);
        
        checkToString(accuracy, "3.002001");
    }
    
    public void testTwoThreeTwo()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(TWO_VALUE, THREE_VALUE, TWO_VALUE));
        
        checkValues(accuracy, TWO_VALUE, THREE_VALUE, TWO_VALUE);
        
        checkToString(accuracy, "2.003002");
    }
    

    public void testZeroTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, TWO_VALUE, THREE_VALUE));
        
        checkValues(accuracy, ZERO_VALUE, TWO_VALUE, THREE_VALUE);
        
        checkToString(accuracy, "0.002003");
    }

    public void testThreeTwoNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, null));
        
        checkValues(accuracy, THREE_VALUE, TWO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "3.002000");
    }
    
    public void testOneNullOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, null, ONE_VALUE));
        
        checkValues(accuracy, ONE_VALUE, ZERO_VALUE, ONE_VALUE);
        
        checkToString(accuracy, "1.000001");
    }
    
    public void testZeroNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, null, null));
        
        checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "0.000000");
    }
    
    public void testNullNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(null, null, null));
        
        checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "0.000000");
    }
    
    private void checkValues(
        GenTimeAccuracy accuracy,
        DERInteger      secs,
        DERInteger      millis,
        DERInteger      micros)
    {
        assertEquals(secs.getValue().intValue(), accuracy.getSeconds());
        assertEquals(millis.getValue().intValue(), accuracy.getMillis());
        assertEquals(micros.getValue().intValue(), accuracy.getMicros());
    }
    
    private void checkToString(
        GenTimeAccuracy accuracy,
        String          expected)
    {
        assertEquals(expected, accuracy.toString());
    }
}
