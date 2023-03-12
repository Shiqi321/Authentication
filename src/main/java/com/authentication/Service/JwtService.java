package com.authentication.Service;

import com.authentication.Model.TokenResponse;

import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.authentication.Util.RedisUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Key;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    @Autowired
    private SecretKeyPairService secretKeyPairService;

    @Autowired
    private RedisUtil redisUtil;

    @Value("${jwt.alg}")
    private String alg;
    @Value("${jwt.typ}")
    private String typ;
    @Value("${jwt.issuer}")
    private String issuer;
    @Value("${jwt.access_token_expiration}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh_token_expiration}")
    private long refreshExpriation;
    @Value("${jwt.audience}")
    private String audience;

    @Value("${secret.access_pvt}")
    private String access_pvt;

    @Value("${secret.access_pub}")
    private String access_pub;

    @Value("${secret.refresh_pvt}")
    private String refresh_pvt;

    @Value("${secret.refresh_pub}")
    private String refresh_pub;

    private final String ALGORITHMN = "alg";
    private final String TYPE = "typ";
    private final String ISSUER = "issuer";
    private final String ADU= "aud";
    private final String EXP = "exp";
    private final String USER = "user";
    private final String ISSUAT = "issueAt";
    private final String TOKEN_TYPE = "tokenType";

    public String generateToken(String userId, boolean isRefreshToken, int type) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        //create header
        Map<String, Object> headers = new HashMap<>();
        headers.put(ALGORITHMN, alg);
        headers.put(TYPE, typ);
        //set claims
        long current = System.currentTimeMillis();
        long expirationTime = current + (isRefreshToken ? refreshExpriation : accessTokenExpiration) * 1000L;
        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, issuer);
        claims.put(ADU, audience);
        claims.put(EXP, expirationTime);
        claims.put(ISSUAT, current);
        claims.put(USER, userId);
        claims.put(TOKEN_TYPE, type);
        Key secret = secretKeyPairService.loadPrivateKey((isRefreshToken? refresh_pvt : access_pvt));
        JwtBuilder builder = Jwts.builder();
        builder.setHeader(headers);
        builder.setClaims(claims);
        builder.signWith(SignatureAlgorithm.forName(alg), secret);
        return builder.compact();
    }

    public TokenResponse verifyToken(String userId, String token, boolean isRefreshToken) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException {
        if (!token.contains("Bearer")) {
            return TokenResponse.ChangedResponse;
        }
        token =  token.replace("Bearer","").trim();
        String key = userId + "-";
        if (isRefreshToken) {
            key = key  + "refresh_token";
            if (redisUtil.sHasKey(key, token)) {
                return TokenResponse.TypeErrorResponse;
            }
        } else {
            key = key + "access_token";
            if (redisUtil.hasKey(key)) {
                return TokenResponse.TypeErrorResponse;
            }
        }

        String[] chunks = token.split("\\.");
        if (chunks.length != 3) {
            return TokenResponse.ChangedResponse;
        }
        Base64.Decoder decoder = Base64.getUrlDecoder();
        ObjectMapper mapper = new ObjectMapper();
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        Key secret = secretKeyPairService.loadPublicKey((isRefreshToken? refresh_pub : access_pub));
        Header headers = Jwts.parser().setSigningKey(secret).parse(token).getHeader();
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

        if (!mapper.readValue(header, Map.class).equals(headers) || !mapper.readValue(payload, Map.class).equals(claims)) {
            return TokenResponse.ChangedResponse;
        }

        if (!claims.get(USER).equals(userId) || !claims.get(ISSUER).equals(issuer) || !claims.get(ADU).equals(audience)) {
            return TokenResponse.InforErrorResponse;
        }

        long expirationTime = (Long)claims.get(EXP);
        long currentTime = System.currentTimeMillis();
        if (expirationTime < currentTime) {
            return TokenResponse.ExpirationResponse;
        }
        return TokenResponse.MatchResponse;
    }

    public long getTokenExpiration(String token) throws IOException {
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        ObjectMapper mapper = new ObjectMapper();
        String payload = new String(decoder.decode(chunks[1]));
        Map claims =  mapper.readValue(payload, Map.class);
        return (Long)claims.get(EXP);
    }

    public void invalidateToken(String userId, String token, boolean isRefresh) throws NoSuchAlgorithmException, URISyntaxException, InvalidKeySpecException, IOException {
        TokenResponse tokenResponse = verifyToken(userId, token, isRefresh);
        if (tokenResponse.equals(TokenResponse.MatchResponse)) {
            long expiration = getTokenExpiration(token) - System.currentTimeMillis();
            String key = userId + "-";
            if (isRefresh) {
                key = key  + "refresh_token";
                redisUtil.sSetAndTime(key, expiration, token);
            } else {
                key = key + "access_token";
                redisUtil.set(key, token, expiration);
            }

        }

    }

}
