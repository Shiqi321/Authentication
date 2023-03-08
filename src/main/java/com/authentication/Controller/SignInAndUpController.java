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
import org.apache.ibatis.annotations.Param;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
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
        UserLoginInfo fullInfo = userInfoOperationService.getMatched(userLoginInfo.getUsername(),
                userLoginInfo.getPassword());
        try {
            if (fullInfo != null) {
                String accessToken = jwtService.generateToken(fullInfo.getUserId(), false, 0);
                String refreshToken = jwtService.generateToken(fullInfo.getUserId(), true, 0);
                jwtService.insertRefreshToken(refreshToken);
                HashMap<String, String> data = new HashMap<>();
                data.put("access_token", accessToken);
                data.put("refresh_token", refreshToken);
                return ResultData.success(data);
            } else {
                int isVerified = userInfoOperationService.getIsVerified(userLoginInfo.getUsername());
                if (isVerified == 0) {
                    return ResultData.error(Error.VerifiedException);
                }
                String userId = userInfoOperationService.getUserId(userLoginInfo.getUsername());
                if (StringUtils.isNullOrEmpty(userId)) {
                    return ResultData.error(Error.MatchedException);
                } else {
                    return ResultData.error(Error.UserNameException);
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

    }

    @PostMapping("/signUp")
    public ResultData signUp(UserLoginInfo userLoginInfo) throws NoSuchAlgorithmException {
        secretKeyPairService.generateKeyPair();
        String userId = userInfoOperationService.getUserId(userLoginInfo.getUsername());
        if (!StringUtils.isNullOrEmpty(userId)) {
            return ResultData.error(Error.ExistException);
        }
        userLoginInfo = userInfoOperationService.insertNewUser(userLoginInfo);

        try {

            emailService.sendVerificationEmail(userLoginInfo.getUsername(), 0);
            return ResultData.success("please verify your email!");
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

    }

    @GetMapping("/verifyEmail")
    public ResultData verifyEmail(@Param("username")String username,
                                  @Param("token")String token,
                                  @Param("type")int type) {
        String userId = userInfoOperationService.getUserId(username);
        if (StringUtils.isNullOrEmpty(userId)) {
            return ResultData.error(Error.UserNameException);
        }
        int isVerified = userInfoOperationService.getIsVerified(username);
        if (isVerified == 1) {
            return ResultData.success("already verify the email");
        }
        try {
            TokenResponse tokenResponse = emailService.verifiedToken(userId, token, type);
            if (!tokenResponse.equals(TokenResponse.MatchResponse)) {
                return ResultData.error(401, tokenResponse.getMessage());
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }
        return ResultData.success("verify the email successfully");
    }

    @GetMapping("/restPassword")
    public ResultData restPassword(UserLoginInfo userLoginInfo) {
        String userId = userInfoOperationService.getUserId(userLoginInfo.getUsername());
        if (StringUtils.isNullOrEmpty(userId)) {
            return ResultData.error(Error.UserNameException);
        }
        try {
            emailService.sendVerificationEmail(userLoginInfo.getUsername(), 1);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return ResultData.error(Error.ServiceException);
        }

        return ResultData.success("reset password email sent successfully!");
    }
    //for test
    @GetMapping("/generate_secret")
    public void generate() throws NoSuchAlgorithmException {
        secretKeyPairService.generateKeyPair();
    }
}
