package org.example;

import java.security.SecureRandom;

public class AES {

    public byte[] generowanieklucza(){
        int liczbabajtow = 16;

        byte[] bity = new byte[liczbabajtow];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bity);
        return  bity;
    }
}
