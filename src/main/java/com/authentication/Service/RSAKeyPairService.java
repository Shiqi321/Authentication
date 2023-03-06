package com.authentication.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class RSAKeyPairService {
    protected Logger logger = LoggerFactory.getLogger(RSAKeyPairService.class);
    @Value("${keyPair.alg}")
    private String alg;
    @Value("${keyPair.size}")
    private int size;

    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(size);
        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();
        try {
            storeKeys("public", pub);
            storeKeys("private", pvt);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }

    private void storeKeys(String file, Key key) throws IOException {
        Base64.Encoder encoder = Base64.getEncoder();
        Writer out = new FileWriter(file + ".key");
        out.write("-----BEGIN KEY-----\n");
        out.write(encoder.encodeToString(key.getEncoded()));
        out.write("\n-----END KEY-----\n");
        out.close();
    }


}
