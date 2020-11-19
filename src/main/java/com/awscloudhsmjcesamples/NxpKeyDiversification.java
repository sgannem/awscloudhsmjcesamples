/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.awscloudhsmjcesamples;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumDES3Key;
import com.cavium.key.CaviumECPrivateKey;
import com.cavium.key.CaviumECPublicKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * This sample demonstrates how to work with keys. This could be generating diversified key based diversification
 * algorithm specified in page no.5 of https://www.nxp.com/docs/en/application-note/AN10922.pdf document.
 * Algorithm:
 * 1. Calculate CMAC input D:
 * 2. D 0x01 || M || Padding
 * 3. Padding is chosen such that D always has a length of 32 bytes. Padding bytes are
 * according to the CMAC padding, i.e. 80h followed by 00h bytes. So the length of
 * Padding is 0 to 30 bytes.
 * 4. Calculate the Boolean flag ‘Padded’, which is true if M is less than 31 bytes long, false
 * otherwise. The Boolean argument “Padded” is needed because it must be known in
 * AES128CMAC which K1 or K2 is to be used in the last computation round.
 * 5. Calculate output:
 * 6. Diversified Key AES128CMAC (K, D, Padded)
 */
public class NxpKeyDiversification {

    public static final byte BRB = (byte) 0x87; // Rb for AES128
    public static final String CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING";
    public static final String AES_CIPHER_NO_PADDING = "AES/CBC/NoPadding";
    public static final String ECB_NOPADDING = "AES/ECB/NoPadding";
    public static final String CAVIUM = "Cavium";
    public static final byte[] Z16 = new byte[16]; // 128 bit zero
    public static final IvParameterSpec ZERO_IV = new IvParameterSpec(new byte[16]);
    public static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private static String helpString = "NxpKeyDiversification\n" +
            "This sample demonstrates nxp key diversification utility method for working with keys in the " +
      "HSM.\n" +
            "\n" +
            "Options\n"+
            "\t--nxp-div\t\tTest NXP Key Diversification\n\n"+
            "\t--masterKeyHandle <masterKeyId(AES128)>\n" +
            "\t--kekHandle <KEKId(AES128)>\n" +
            "\t--divInput <divInput>\n" +
            "\t--threadPoolSize <threadPoolSize>\n" +
            "\t--totalRequestSize <totalRequestSize>\n" +
            "\t--user <username>\n" +
            "\t--password <password>\n" +
            "\t--partition <partition>\n\n";

    public enum modes {
        INVALID,
        NXP_DIV
    }

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        long masterkeyHandle = 0;
        long kekHandle = 0;
        int threadPoolSize=0;
        int totalRequestSize=0;
        String divInput =null;
        modes mode = modes.INVALID;
        String user = null;
        String pass = null;
        String partition = null;
        System.out.println("#Got length of inputs params:"+args.length);
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            System.out.println("#Got length of input parameter:"+arg);
            switch (arg) {
                case "--divInput":
                    divInput = args[++i];
                    System.out.println(divInput);
                    break;
                case "--masterKeyHandle":
                    masterkeyHandle = Integer.valueOf(args[++i]);
                    break;
                case "--kekHandle":
                    kekHandle = Integer.valueOf(args[++i]);
                    break;
                case "--nxp-div":
                    mode = modes.NXP_DIV;
                    break;
                case "--user":
                    user = args[++i];
                    break;
                case "--password":
                    pass = args[++i];
                    break;
                case "--partition":
                    partition = args[++i];
                    break;
                case "--threadPoolSize":
                    threadPoolSize = Integer.valueOf(args[++i]);
                    break;
                case "--totalRequestSize":
                    totalRequestSize = Integer.valueOf(args[++i]);
                    break;
            }
        }

        if (modes.NXP_DIV == mode && null == divInput && 0 == masterkeyHandle && 0 == kekHandle && 0 == threadPoolSize && 0==totalRequestSize) {
            System.out.println("Please specify one of divInput or masterKeyHandle or kekHandle or threadPoolSize or totalRequestSize");
            help();
            return;
        } else {
            System.out.println("################## EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE #####################");
        }


        /** logging to hsm **/
        System.out.println("#Logging into HSM with user:" + user);
        loginWithExplicitCredentials(user, pass, partition);
        System.out.println("#Logged into HSM with user:" + user + " successful...");
        System.out.println("# Operating key import operations ...");
//        // Using the supplied label, find the associated key handle.
//        // The handle for the *first* key found using the label will be the handle returned.
//        // If multiple keys have the same label, only the first key can be returned.
//        if (0 == handle && modes.IMPORT_KEY != mode && modes.IMPORT_PEM != mode) {
//            System.out.println("#Handle is 0 and mode is:"+mode+", hence finding all label associated key handles...");
//            try {
//                long[] handles = {0};
//                Util.findKey(label, handles);
//                System.out.println("#Found the following list of handles:"+ Arrays.toString(handles));
//                handle = handles[0];
//                System.out.println("#Extracted first key handle:"+handle);
//            } catch (CFM2Exception ex) {
//                if (CFM2Exception.isAuthenticationFailure(ex)) {
//                    System.out.println("Could not find credentials to login to the HSM");
//                    return;
//                }
//
//                throw ex;
//            }
//        }
//        doProcess(mode, pemFile, handle);

        SecretKey maserKey = (SecretKey) getKey(masterkeyHandle);
        displayKeyInfo(maserKey);
        SecretKey kek = (SecretKey)  getKey(masterkeyHandle);
        displayKeyInfo(kek);
        AtomicLong al = new AtomicLong(0L);
        ExecutorService executorService = Executors.newFixedThreadPool(threadPoolSize);
        Map<Long, Future<String>> mapOfFutures = new HashMap<>();
        final String divInputFinal = divInput;
        for(int i=0;i<totalRequestSize;i++) {
            long executionId = al.incrementAndGet();
            mapOfFutures.put(executionId,executorService.submit(new Callable<String>() {
                @Override
                public String call() throws Exception {
                    return doDiversificationwithElapsedTime(divInputFinal, maserKey, kek, executionId);
                }
            }));
        }
        /** its blocking to get all the results **/
        mapOfFutures.forEach((tempKey, tempValue) -> {
            try {
                System.out.println(tempValue.get());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        executorService.shutdown();
        System.out.println("#Now it is logging out ...");
        logout();
        System.out.println("#Logged out from hsm successful...");
        /** logging out hsm **/

        /**


         **/
    }

    private static String doDiversificationwithElapsedTime(String divInput, SecretKey maserKey, SecretKey kek,
      long executionId) throws Exception {
        long startTime = System.nanoTime();
        byte[] diversifiedKey = doDiversification(maserKey, divInput);
        byte[] encryptedDivKey = encryptKey(kek, diversifiedKey);
//        System.out.println("#############################################################");
//        System.out.println("#Got diversifiedKey:"+toHexString(diversifiedKey));
//        System.out.println("#Got encryptedDivKey:"+toHexString(encryptedDivKey));
//        System.out.println("#############################################################");
        long elapsedTime = System.nanoTime() - startTime;
        String finalResult = "#Execution Id:"+executionId+", Total time taken(ms):"+(elapsedTime/1000000L)+" Got " +
          "encryptedDivKey:"+toHexString(encryptedDivKey);
        System.out.println(finalResult);
        return finalResult;
    }

    private static void help() {
        System.out.println(helpString);
    }

    public static CaviumKey getKey(long keyHandle) throws KeyException {
        System.out.println("#calling getKey({})" + keyHandle);
        try {
            byte[] keyAttribute = Util.getKeyAttributes(keyHandle);
            CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
            switch (cka.getKeyType()) {
                case CaviumKeyAttributes.KEY_TYPE_AES:
                    return new CaviumAESKey(keyHandle, cka);
                case CaviumKeyAttributes.KEY_TYPE_DES:
                case CaviumKeyAttributes.KEY_TYPE_DES3:
                    return new CaviumDES3Key(keyHandle, cka);
                case CaviumKeyAttributes.KEY_TYPE_RSA:
                    switch (cka.getKeyClass()) {
                        case CaviumKeyAttributes.CLASS_PRIVATE_KEY:
                            return new CaviumRSAPrivateKey(keyHandle, cka);
                        case CaviumKeyAttributes.CLASS_PUBLIC_KEY:
                            return new CaviumRSAPublicKey(keyHandle, cka);
                        default:
                            return null;
                    }
                case CaviumKeyAttributes.KEY_TYPE_EC:
                    switch (cka.getKeyClass()) {
                        case CaviumKeyAttributes.CLASS_PRIVATE_KEY:
                            return new CaviumECPrivateKey(keyHandle, cka);
                        case CaviumKeyAttributes.CLASS_PUBLIC_KEY:
                            return new CaviumECPublicKey(keyHandle, cka);
                        default:
                            return null;
                    }
                default:
                    return null;
            }
        } catch (CFM2Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void displayKeyInfo(Key k) {
        CaviumKey key = (CaviumKey)k;
        if (null != key) {
            System.out.printf("Key handle %d with label %s\n", key.getHandle(), key.getLabel());
            // Display whether the key can be extracted from the HSM.
            System.out.println("Is Key Extractable? : " + key.isExtractable());

            // Display whether this key is a token key.
            System.out.println("Is Key Persistent? : " + key.isPersistent());

            // The algorithm and size used to generate this key.
            System.out.println("Key Algo : " + key.getAlgorithm());
            System.out.println("Key Size : " + key.getSize());
        }
    }

    /**
     * The explicit login method allows users to pass credentials to the Cluster manually. If you obtain credentials
     * from a provider during runtime, this method allows you to login.
     *
     * @param user      Name of CU user in HSM
     * @param pass      Password for CU user.
     * @param partition HSM ID
     */
    public static void loginWithExplicitCredentials(String user, String pass, String partition) {
        LoginManager lm = LoginManager.getInstance();
        try {
            lm.login(partition, user, pass);
            System.out.printf("\nLogin successful!\n\n");
        } catch (CFM2Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                System.out.printf("\nDetected invalid credentials\n\n");
            }

            e.printStackTrace();
        }
    }

    /**
     * Logout will force the LoginManager to end your session.
     */
    public static void logout() {
        try {
            LoginManager.getInstance().logout();
        } catch (CFM2Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] doDiversification(SecretKey secretKey, String divInput1) {
            // Step 1
            Cipher cipher = null;
            SecretKey skeySpec = secretKey;
            // 128 bit sub key
            byte[] k1 = new byte[16];
            try {
                cipher = Cipher.getInstance(ECB_NOPADDING, CAVIUM);
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                k1 = cipher.doFinal(Z16);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean highL = ((k1[0] & 0x80) != 0);
            k1 = shl(k1);
            if (highL) {
                k1[15] = (byte) (k1[15] ^ BRB);
            }
            highL = ((k1[0] & 0x80) != 0);

            // 128 bit sub key
            byte[] k2 = shl(k1);
            if (highL) {
                k2[15] = (byte) (k2[15] ^ BRB);
            }
            byte[] diversifiedKey = null;
            try {
                diversifiedKey = getDiversifiedKey(divInput1, CAVIUM, skeySpec, k1, k2);
            } catch (Exception e) {
                e.printStackTrace();
            }

            return diversifiedKey;
        }

    private static byte[] getDiversifiedKey(String divInput, String provider, SecretKey skeySpec, byte[] k1,
      byte[] k2) throws Exception {
        Cipher cipher;
        byte[] xoredD = generateXoredD(divInput, k1, k2);
        cipher = Cipher.getInstance(CBC_PKCS5PADDING, provider);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ZERO_IV);
        byte[] encrypted = cipher.doFinal(xoredD);
        byte[] dkey = Arrays.copyOfRange(encrypted, 16, 32);
        return dkey;
    }

    public static byte[] generateXoredD(String divInput, byte[] k1, byte[] k2) throws IOException {
        // Step 5

        // Step 6
        // Step 7
        byte[] divInput1Bytes = hexStringToByteArray(divInput);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(divInput1Bytes);

        // Step 8 & 9
        byte[] c = outputStream.toByteArray();

        // Step 10 & 11
        boolean padded = false;
        if (c.length < 32) {
            padded = true;
            byte[] eg = hexStringToByteArray("80");
            outputStream.write(eg);
            byte[] st = outputStream.toByteArray();

            byte[] end = new byte[32 - st.length];

            outputStream.write(end);

            c = outputStream.toByteArray();
            outputStream.close();
        }

        byte[] xorComponent;
        if (padded) {
            xorComponent = k2;
        } else {
            xorComponent = k1;
        }

        int mz = c.length;
        int n = mz / 16;

        byte[] mLast = new byte[16];
        int lastn = (n - 1) * 16;
        int lastz = mz - lastn;
        System.arraycopy(c, lastn, mLast, 0, lastz);
        byte[] first = Arrays.copyOfRange(c, 0, 16);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(first);
        stream.write(xor16(mLast, xorComponent));
        return stream.toByteArray();
    }

    public static byte[] shl(byte[] bin) {
        // << 16 byte array
        byte[] bout = new byte[16];
        // java b[0] is the highorder
        for (short j = 0; j < 15; j++) {
            int sot = ((bin[j + 1] & 0x80) >> 7);
            int sef = (bin[j] << 1) | sot;
            bout[j] = (byte) sef;
        }
        bout[15] = (byte) (bin[15] << 1);
        return bout;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] xor16(byte[] ba, byte[] bb) {
        byte[] bout = new byte[ba.length];
        for (short j = 0; j < ba.length; j++) {
            bout[j] = (byte) (ba[j] ^ bb[j]);
        }
        return bout;
    }

    public static String toHexString(byte[] bytes) {
        if (null == bytes) {
            return null;
        }
        StringBuilder sb = new StringBuilder(bytes.length << 1);
        for (int i = 0; i < bytes.length; ++i) {
            sb.append(HEX[(bytes[i] & 0xf0) >> 4])
              .append(HEX[(bytes[i] & 0x0f)]);
        }
        return sb.toString();
    }

    private static byte[] encryptKey(Key key, byte[] data) throws Exception {
        System.out.println("Entering encryptKey...");
        byte[] kekEncryptedKey = null;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_CIPHER_NO_PADDING, CAVIUM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            kekEncryptedKey = cipher.doFinal(data);
        } catch (Exception e) {
           e.printStackTrace();
        }
        System.out.println("Exiting encryptKey...");
        return kekEncryptedKey;
    }

}
