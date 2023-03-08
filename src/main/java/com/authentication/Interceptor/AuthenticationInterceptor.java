package com.authentication.Interceptor;

import com.authentication.Model.TokenResponse;
import com.authentication.Service.JwtService;
import com.mysql.cj.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuthenticationInterceptor implements HandlerInterceptor {
    private Logger logger = LoggerFactory.getLogger(AuthenticationInterceptor.class);

    @Autowired
    JwtService jwtService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            String token = request.getHeader("token").replace("Bearer ","");
            String userId = request.getHeader("user_id");
            if (StringUtils.isNullOrEmpty(userId)) {
                return false;
            }
            return jwtService.verifyToken(userId, token, false).equals(TokenResponse.MatchResponse);

        } catch (Exception e) {
            logger.error("Error occured while authenticating request : " + e.getMessage());
        }
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        return false;
    }
}
