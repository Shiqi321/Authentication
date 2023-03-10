package com.authentication.Service;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.transfer.s3.S3TransferManager;
import software.amazon.awssdk.transfer.s3.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.stereotype.Service;
import software.amazon.awssdk.transfer.s3.progress.LoggingTransferListener;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


@Service
public class SecretKeyPairService {
    protected Logger logger = LoggerFactory.getLogger(SecretKeyPairService.class);
    @Value("${keyPair.alg}")
    private String alg;
    @Value("${keyPair.size}")
    private int size;

    @Value("${puk.access_token.bucket}")
    private String pubAccessBucketName;
    @Value("${puk.access_token.key}")
    private String pubAccessKeyName;

    @Value("${puk.refresh_token.bucket}")
    private String pubRefreshBucketName;
    @Value("${puk.refresh_token.key}")
    private String pubRefreshKeyName;

    @Value("${pvt.access_token.bucket}")
    private String pvtAccessBucketName;
    @Value("${pvt.access_token.key}")
    private String pvtAccessKeyName;

    @Value("${pvt.refresh_token.bucket}")
    private String pvtRefreshBucketName;
    @Value("${pvt.refresh_token.key}")
    private String pvtRefreshKeyName;


    public void writePemFile(Key key, String description, String filename)
            throws IOException {
        PemObject pemObject = new PemObject(description, key.getEncoded());
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(pemObject);
        } finally {
            pemWriter.close();
        }

        logger.info(String.format("%s successfully writen in file %s.", description, filename));
    }

    public Key loadPublicKey(String file, boolean isRefresh) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File pubFile = new File(file);
        if (!pubFile.exists() || pubFile.length() == 0) {
            String bucketName = isRefresh ? pubRefreshBucketName : pubAccessBucketName;
            String keyName = isRefresh? pubRefreshKeyName : pubAccessKeyName;
            downloadFromAws(bucketName, keyName);
            pubFile = new File(file);
        }
        String key = new String(Files.readAllBytes(pubFile.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance(alg);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        PublicKey pub = keyFactory.generatePublic(keySpec);
        return pub;
    }

    public Key loadPrivateKey(String file, boolean isRefresh) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File ptvFile = new File(file);
        if (!ptvFile.exists() || ptvFile.length() == 0) {
            String bucketName = isRefresh ? pvtRefreshBucketName : pvtAccessBucketName;
            String keyName = isRefresh? pvtRefreshKeyName : pvtAccessKeyName;
            downloadFromAws(bucketName, keyName);
            ptvFile = new File(file);
        }
        String key = new String(Files.readAllBytes(ptvFile.toPath()), Charset.defaultCharset());
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(alg);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey pvt = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        if (!ptvFile.delete()) {
            logger.error("fail to delete private key: " + file);
        }
        return pvt;
    }

    public void downloadFromAws(String bucketName, String keyName) {
        S3TransferManager transferManager = S3TransferManager.create();
        downloadFile(transferManager, bucketName, keyName, keyName);
    }

    public Long downloadFile(S3TransferManager transferManager, String bucketName,
                             String key, String downloadedFileWithPath) {
        DownloadFileRequest downloadFileRequest =
                DownloadFileRequest.builder()
                        .getObjectRequest(b -> b.bucket(bucketName).key(key))
                        .addTransferListener(LoggingTransferListener.create())
                        .destination(Paths.get(downloadedFileWithPath))
                        .build();

        FileDownload downloadFile = transferManager.downloadFile(downloadFileRequest);

        CompletedFileDownload downloadResult = downloadFile.completionFuture().join();
        logger.info("Content length [{}]", downloadResult.response().contentLength());
        return downloadResult.response().contentLength();
    }

}
