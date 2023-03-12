package com.authentication.Util;

import com.google.common.hash.Hashing;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class Utils {

    public static final String REG_NUMBER = ".*\\d+.*";

    public static final String REG_UPPERCASE = ".*[A-Z]+.*";

    public static final String REG_LOWERCASE = ".*[a-z]+.*";

    public static final String REG_SYMBOL = ".*[~!@#$%^&*()_+|<>,.?/:;'\\[\\]{}\"]+.*";
    public static boolean checkPasswordRule(String password){

        if (password == null || password.length() < 8 || password.length() > 20) {
            return false;
        }

        int result = 0;
        if (password.matches(REG_NUMBER)) {
            result++;
        }
        if (password.matches(REG_LOWERCASE)) {
            result++;
        }
        if (password.matches(REG_UPPERCASE)) {
            result++;
        };
        if (password.matches(REG_SYMBOL)) {
            result++;
        }
        return result >= 4;
    }
    public static String saltHash(String salt, String hash) {
        return Hashing.sha256().hashString(salt + hash, StandardCharsets.UTF_8).toString();
    }

    public static boolean checkEmailFormat(String email) {
        String REGEX="^\\w+((-\\w+)|(\\.\\w+))*@\\w+(\\.\\w{2,3}){1,3}$";
        Pattern p = Pattern.compile(REGEX);
        Matcher matcher=p.matcher(email);
        return matcher.matches();
    }
}
