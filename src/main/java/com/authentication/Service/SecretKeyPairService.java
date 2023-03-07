package com.authentication.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class SecretKeyPairService {
    protected Logger logger = LoggerFactory.getLogger(SecretKeyPairService.class);
    @Value("${keyPair.alg}")
    private String alg;
    @Value("${keyPair.size}")
    private int size;

    @Async
    @Scheduled(cron = "* * * * */3 *")
    public void generateKeyPair() throws NoSuchAlgorithmException {
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

    public void storeKeys(String file, Key key) throws IOException {
        FileOutputStream out = new FileOutputStream(file + ".key");
        out.write(key.getEncoded());
        out.close();
    }

    public Key loadPublicKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(file);
        byte[] bytes = Files.readAllBytes(path);
        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(alg);
        PublicKey pub = kf.generatePublic(ks);
        return pub;

    }

    public Key loadPrivateKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(file);
        byte[] bytes = Files.readAllBytes(path);
        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

}
