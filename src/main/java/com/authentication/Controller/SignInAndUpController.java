package com.authentication.Controller;

import com.authentication.Model.Error;
import com.authentication.Model.ResultData;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Service.AuthenticateUserService;
import com.authentication.Service.EmailService;
import com.authentication.Service.JwtService;
import com.authentication.Service.UserInfoOperationService;
import com.mysql.cj.util.StringUtils;
import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.mail.MessagingException;
import java.util.HashMap;

@RestController
public class SignInAndUpController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticateUserService authenticateUserService;
    @Autowired
    private UserInfoOperationService userInfoOperationService;
    @Autowired
    private EmailService emailService;

    @PostMapping("/login")
    public ResultData login(UserLoginInfo userLoginInfo) {
        UserLoginInfo fullInfo = authenticateUserService.getMatched(userLoginInfo.getUsername(),
                userLoginInfo.getPassword());
        if (fullInfo != null) {
            String accessToken = jwtService.generateToken(fullInfo.getUserId(), false);
            String refreshToken = jwtService.generateToken(fullInfo.getUserId(), true);
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
    }

    @PostMapping("/signUp")
    public ResultData signUp(UserLoginInfo userLoginInfo) throws MessagingException {
        String userId = userInfoOperationService.getUserId(userLoginInfo.getUsername());
        if (!StringUtils.isNullOrEmpty(userId)) {
            return ResultData.error(Error.ExistException);
        }
        userInfoOperationService.insertNewUser(userLoginInfo);
        String token = jwtService.generateToken(userId, false);
        emailService.sendVerificationEmail(userLoginInfo.getUsername(), token);
        return ResultData.success("please verify your email!");
    }

    @GetMapping("/verifyEmail")
    public ResultData verifyEmail(@Param("username")String username) {
        userInfoOperationService.verifiedEmail(username);
        return ResultData.success("verify the email successfully");
    }

    @GetMapping("/forgetPassword")
    public ResultData forgetPassword(@Param("username")String username) {
        String userId = userInfoOperationService.getUserId(username);
        if (StringUtils.isNullOrEmpty(userId)) {
            return ResultData.error(Error.UserNameException);
        }

        return ResultData.success("reset password email has sent");
    }
}
