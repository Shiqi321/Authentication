package com.authentication.Controller;

import com.authentication.Model.Error;
import com.authentication.Model.ResultData;
import com.authentication.Model.TokenResponse;
import com.authentication.Service.JwtService;
import com.mysql.cj.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
public class refreshTokenController {
    private Logger logger = LoggerFactory.getLogger(RequestSourcesController.class);

    @Autowired
    private JwtService jwtService;

    @GetMapping("/refreshToken")
    public ResultData refreshToken(@RequestHeader("access_token") String accessToken,
                                   @RequestHeader("refresh_token") String refreshToken,
                                   @RequestHeader("user_id")String userId) {
        try {
            TokenResponse accessTokenResponse = jwtService.verifyToken(userId, accessToken, false);
            TokenResponse refreshTokenResponse = jwtService.verifyToken(userId, refreshToken, true);
            if (accessTokenResponse.equals(TokenResponse.ExpirationResponse) && refreshTokenResponse.equals(TokenResponse.MatchResponse)) {
                String refreshId = jwtService.getRefreshId(refreshToken);
                int isUsed = jwtService.getIsUsed(refreshId);
                String familyId = jwtService.getFamilyId(refreshId);
                if (isUsed == 0) {
                    if (!StringUtils.isNullOrEmpty(familyId)) {
                        jwtService.setIsUsedByFamilyId(0, familyId);
                    }
                    return ResultData.error(Error.ReautheticationException);
                }
                if (!StringUtils.isNullOrEmpty(familyId)) {
                    int familyIdIsUsed = jwtService.getIsUsed(familyId);
                    if (familyIdIsUsed == 0) {
                        jwtService.setIsUsed(0, refreshId);
                        return ResultData.error(Error.ReautheticationException);
                    }
                }
                accessToken = jwtService.generateToken(userId, false, 0);
                String newRefreshToken = jwtService.generateToken(userId, false, 0);
                jwtService.insertRefreshToken(newRefreshToken);
                if (!StringUtils.isNullOrEmpty(familyId)) {
                    jwtService.insertFamilyRefreshToken(jwtService.getRefreshId(newRefreshToken), familyId);
                }
                HashMap<String, String> data = new HashMap<>();
                data.put("access_token", accessToken);
                data.put("refresh_token", newRefreshToken);
                return ResultData.success(data);
            } else {
                String refreshId = jwtService.getRefreshId(refreshToken);
                jwtService.setIsUsed(0, refreshId);
                String familyId = jwtService.getFamilyId(refreshId);
                if (!StringUtils.isNullOrEmpty(familyId)) {
                    jwtService.setIsUsedByFamilyId(0, familyId);
                }
                return ResultData.error(Error.ReautheticationException);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

    }
}
