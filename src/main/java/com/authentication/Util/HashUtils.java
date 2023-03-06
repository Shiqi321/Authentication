package com.authentication.Util;

import com.google.common.hash.Hashing;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class HashUtils {

    public static String saltHash(String salt, String hash) {
        return Hashing.sha256().hashString(salt + hash, StandardCharsets.UTF_8).toString();
    }
}
