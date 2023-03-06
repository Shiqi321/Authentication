package com.authentication.Service;

import com.authentication.Dao.RefreshTokenMapperDao;
import com.authentication.Model.RefreshToken;
import com.authentication.Model.RefreshTokenFamily;
import com.authentication.Model.TokenResponse;
import java.util.UUID;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
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
    @Value("${jwt.aduience}")
    private String audience;

    @Autowired
    private RefreshTokenMapperDao refreshTokenMapperDao;


    private final String ALGORITHMN = "alg";
    private final String TYPE = "typ";
    private final String ISSUER = "issuer";
    private final String ADU= "aud";
    private final String EXP = "exp";
    private final String USER = "user";
    private final String ISSUAT = "issueAt";

    public String generateToken(String userId, boolean isRefreshToken) {
        //create header
        Map<String, Object> headers = new HashMap<>();
        headers.put(ALGORITHMN, alg);
        headers.put(TYPE, typ);
        //set claims
        long current = System.currentTimeMillis();
        Date expirationTime = new Date( current + (isRefreshToken ? refreshExpriation : accessTokenExpiration) * 1000L);
        Map<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, issuer);
        claims.put(ADU, userId);
        claims.put(EXP, expirationTime);
        claims.put(ISSUAT, current);
        Key secret = null;
        JwtBuilder builder = Jwts.builder();
        builder.setHeader(headers);
        builder.setClaims(claims);
        builder.signWith(SignatureAlgorithm.forName(alg), secret);
        return builder.compact();
    }

    public TokenResponse verifyToken(String userId, String token) throws IOException {
        String[] chunks = token.split("\\.");
        if (chunks.length != 3) {
            return TokenResponse.ChangedResponse;
        }
        Base64.Decoder decoder = Base64.getUrlDecoder();
        ObjectMapper mapper = new ObjectMapper();
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        Key secret = null;
        Header headers = Jwts.parser().setSigningKey(secret).parse(token).getHeader();
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

        if (!mapper.readValue(header, Map.class).equals(headers) || !mapper.readValue(payload, Map.class).equals(claims)) {
            return TokenResponse.ChangedResponse;
        }

        if (!claims.get(USER).equals(userId)) {
            return TokenResponse.ChangedResponse;
        }

        Date expirationTime = (Date)claims.get(EXP);
        Date currentTime = new Date();
        if (expirationTime.before(currentTime)) {
            return TokenResponse.ExpirationResponse;
        }
        return TokenResponse.MatchResponse;
    }

    public int getIsUsed(String familyId) {
        return refreshTokenMapperDao.getIsUsed(familyId);
    }

    public String getFamilyId(String refreshToken) {
        return refreshTokenMapperDao.getFamilyTokenId(refreshToken);
    }

    public void insertRefreshToken(String refreshToekn) {
        UUID uuid = UUID.randomUUID();
        String refreshId = uuid.toString();
        RefreshToken refreshToken = new RefreshToken(refreshId, refreshToekn, 1);
        refreshTokenMapperDao.insertRefreshToken(refreshToken);
    }

    public void insertFamilyRefreshToken(String refreshToken, String familyId) {
        String refreshTokenId = getRefreshId(refreshToken);
        RefreshTokenFamily refreshTokenFamily = new RefreshTokenFamily(refreshTokenId, familyId);
        refreshTokenMapperDao.insertFamilyRefreshToken(refreshTokenFamily);
    }

    public void setIsUsed(int isUsed, String refreshId) {
        refreshTokenMapperDao.setIsUsed(isUsed, refreshId);
    }

    public void setIsUsedByFamilyId(int isUsed, String familyId) {
        refreshTokenMapperDao.setIsUsedByFamilyId(isUsed, familyId);
    }

    public String getRefreshId(String refreshToken) {
        return refreshTokenMapperDao.getRefreshId(refreshToken);
    }

}
