package com.authentication.Controller;

import com.authentication.Model.Error;
import com.authentication.Model.ResultData;

import com.authentication.Model.TokenResponse;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Service.EmailService;
import com.authentication.Service.JwtService;
import com.authentication.Service.SecretKeyPairService;
import com.authentication.Service.UserInfoOperationService;
import com.mysql.cj.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

@RestController
public class SignInAndUpController {

    private Logger logger = LoggerFactory.getLogger(SignInAndUpController.class);
    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserInfoOperationService userInfoOperationService;
    @Autowired
    private EmailService emailService;

    @Autowired
    private SecretKeyPairService secretKeyPairService;

    @PostMapping("/login")
    public ResultData login(UserLoginInfo userLoginInfo) {
        if (StringUtils.isNullOrEmpty(userLoginInfo.getUsername()) || StringUtils.isNullOrEmpty(userLoginInfo.getPassword())) {
            return ResultData.error(400);
        }

        UserLoginInfo user = userInfoOperationService.getUserByUsername(userLoginInfo.getUsername());
        if (user == null || user.getIsDeleted() == 1 || user.getIsVerified() == 0) {
            return ResultData.error(400);
        }
        try {
            if (userInfoOperationService.getMatched(userLoginInfo.getUsername(), userLoginInfo.getPassword())) {

                if (userInfoOperationService.getLoginTimes(user.getUserId()) > 10) {
                    ResultData.error(403);
                }
                String accessToken = jwtService.generateToken(user.getUserId(), false, 0);
                String refreshToken = jwtService.generateToken(user.getUserId(), true, 0);
                HashMap<String, String> data = new HashMap<>();
                data.put("access_token", accessToken);
                data.put("refresh_token", refreshToken);
                return ResultData.success(data);

            } else {
                return ResultData.error(Error.MatchedException);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

    }

    @PostMapping("/signUp")
    public ResultData signUp(UserLoginInfo userLoginInfo) {
        if (userLoginInfo == null || StringUtils.isNullOrEmpty(userLoginInfo.getUsername()) ||
                StringUtils.isNullOrEmpty(userLoginInfo.getPassword())) {
            return ResultData.error(400);
        }
        UserLoginInfo user = userInfoOperationService.getUserByUsername(userLoginInfo.getUsername());
        if (user != null) {
            return ResultData.error(Error.ExistException);
        }
        userLoginInfo = userInfoOperationService.insertNewUser(userLoginInfo);
        try {
            emailService.sendVerificationEmail(userLoginInfo.getUserId(), userLoginInfo.getUsername(), 0);
            return ResultData.success("please verify your email!");
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

    }

    @GetMapping("/verifyEmail")
    public ResultData verifyEmail(@RequestParam("userId")String userId,
                                  @RequestParam("token")String token,
                                  @RequestParam("type")int type) {

        if (StringUtils.isNullOrEmpty(userId) || StringUtils.isNullOrEmpty(token) || StringUtils.isNullOrEmpty(String.valueOf(type))) {
            return ResultData.error(404);
        }
        UserLoginInfo userLoginInfo = userInfoOperationService.getUserById(userId);
        if (userLoginInfo == null) {
            return ResultData.error(Error.UserNameException);
        }

        if (userLoginInfo.getIsVerified() == 1) {
            return ResultData.success("already verify the email");
        }

        try {
            TokenResponse tokenResponse = emailService.verifiedToken(userLoginInfo.getUserId(), token, type);
            if (!tokenResponse.equals(TokenResponse.MatchResponse)) {
                return ResultData.error(401);
            }
            userLoginInfo.setIsVerified(1);
            userInfoOperationService.updateUser(userLoginInfo);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }
        return ResultData.success("verify the email successfully");
    }

    @GetMapping("/restPassword")
    public ResultData restPassword(UserLoginInfo userLoginInfo,
                                   @RequestParam("original_password") String oldPassword) {
        if (userLoginInfo == null || StringUtils.isNullOrEmpty(userLoginInfo.getUsername()) ||
                StringUtils.isNullOrEmpty(userLoginInfo.getPassword())) {
            return ResultData.error(400);
        }
        userLoginInfo = userInfoOperationService.getUserByUsername(userLoginInfo.getUsername());
        if (userLoginInfo == null || userLoginInfo.getIsDeleted() == 1 || userLoginInfo.getIsVerified() == 0) {
            return ResultData.error(400);
        }
        if (!userInfoOperationService.getMatched(userLoginInfo.getUsername(), oldPassword)) {
            return ResultData.error(400);
        }
        userLoginInfo.setLastUpdateTime(System.currentTimeMillis());
        userInfoOperationService.updateUser(userLoginInfo);
        try {
            emailService.sendVerificationEmail(userLoginInfo.getUserId(), userLoginInfo.getUsername(), 1);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

        return ResultData.success("reset password email sent successfully!");
    }

    @GetMapping("/logout")
    public ResultData logOut(@RequestParam("userId") String userId,
                             @RequestHeader("access_token") String accessToken,
                             @RequestHeader("refresh_token") String refreshToken) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, URISyntaxException {
        if (StringUtils.isNullOrEmpty(userId) || StringUtils.isNullOrEmpty(accessToken) || StringUtils.isNullOrEmpty(refreshToken)) {
            return ResultData.error(400);
        }
        UserLoginInfo userLoginInfo = userInfoOperationService.getUserById(userId);
        if (userLoginInfo == null || userLoginInfo.getIsDeleted() == 1 || userLoginInfo.getIsVerified() == 0) {
            return ResultData.error(400);
        }
        jwtService.invalidateToken(userId, accessToken, false);
        jwtService.invalidateToken(userId, refreshToken, true);
        return ResultData.success();
    }

}
