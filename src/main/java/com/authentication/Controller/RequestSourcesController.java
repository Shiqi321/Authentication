package com.authentication.Controller;

import com.authentication.Model.Error;
import com.authentication.Model.ResultData;
import com.authentication.Model.TokenResponse;
import com.authentication.Service.AuthenticateUserService;
import com.authentication.Service.JwtService;
import com.mysql.cj.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;

@RestController
public class RequestSourcesController {

    @Autowired
    private JwtService jwtService;

    @GetMapping("/requestSources")
    public ResultData requestSources(@RequestHeader("access_token") String accessToken,
                                     @RequestParam("userId")String userId) throws IOException {
        TokenResponse response = jwtService.verifyToken(userId, accessToken);
        if (response.equals(TokenResponse.MatchResponse)) {
            return ResultData.success("prove to request sources");
        }  else if (response.equals(TokenResponse.ExpirationResponse)) {
            return ResultData.error(Error.ExpirationException);
        } else {
            return ResultData.error(Error.TokenException);
        }
    }

    @GetMapping("/refreshToeken")
    public ResultData refreshToken(@RequestHeader("access_token") String accessToken,
                                   @RequestHeader("refresh_token") String refreshToken,
                                   @RequestParam("userId")String userId) throws IOException {
        TokenResponse accessTokenResponse = jwtService.verifyToken(userId, accessToken);
        TokenResponse refreshTokenResponse = jwtService.verifyToken(userId, refreshToken);
        if (accessTokenResponse.equals(TokenResponse.ExpirationResponse) && refreshTokenResponse.equals(TokenResponse.MatchResponse)) {
            int isUsed = jwtService.getIsUsed(refreshToken);
            String familyId = jwtService.getFamilyId(refreshToken);
            if (isUsed == 0) {
                jwtService.setIsUsedByFamilyId(0, familyId);
                return ResultData.error(Error.ReautheticationException);
            }
            int familyIdIsUsed = jwtService.getIsUsed(familyId);
            if (familyIdIsUsed == 0) {
                String refreshId = jwtService.getRefreshId(refreshToken);
                jwtService.setIsUsed(0, refreshId);
                return ResultData.error(Error.ReautheticationException);
            }
            accessToken = jwtService.generateToken(userId, false);
            String newRefreshToken = jwtService.generateToken(userId, false);
            jwtService.insertRefreshToken(newRefreshToken);
            if (!StringUtils.isNullOrEmpty(familyId)) {
                jwtService.insertFamilyRefreshToken(jwtService.getRefreshId(newRefreshToken), familyId);
            }
            HashMap<String, String> data = new HashMap<>();
            data.put("access_token", accessToken);
            data.put("refresh_token", newRefreshToken);
            return ResultData.success(data);
        } else {
            jwtService.setIsUsed(0, refreshToken);
            String familyId = jwtService.getFamilyId(refreshToken);
            jwtService.setIsUsedByFamilyId(0, familyId);
            return ResultData.error(Error.ReautheticationException);
        }

    }
}
