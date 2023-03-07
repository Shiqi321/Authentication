package com.authentication.Service;

import com.authentication.Mapper.UserLoginInfoMapper;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Util.HashUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserInfoOperationService {
    @Autowired
    private UserLoginInfoMapper userLoginInfoMapperDao;
    @Autowired
    private UserInfoOperationService userInfoOperationService;

    public String getUserId(String username) {
        return userLoginInfoMapperDao.getUserId(username);
    }

    public UserLoginInfo getUser(String userId) {
        UserLoginInfo userLoginInfo = userLoginInfoMapperDao.getUser(userId);
        return userLoginInfo;
    }

    public int getIsVerified(String username) {
        return userLoginInfoMapperDao.getIsVerified(username);
    }

    public UserLoginInfo insertNewUser(UserLoginInfo userLoginInfo) {
        String userId = UUID.randomUUID().toString();
        userLoginInfo.setUserId(userId);
        userLoginInfo.setIsVerified(0);
        long currentTime = System.currentTimeMillis();
        userLoginInfo.setSignDateTime(currentTime);
        String salt = String.valueOf(currentTime % 10000);
        String hashedPassword = HashUtils.saltHash(salt, userLoginInfo.getPassword());
        userLoginInfo.setPassword(hashedPassword);
        userLoginInfoMapperDao.insertUser(userLoginInfo);
        return userLoginInfo;
    }

    public void verifiedEmail(int isVerified, String username) {
        userLoginInfoMapperDao.setIsVerified(isVerified, username);
    }

    public UserLoginInfo getMatched(String username, String password) {
        String userId = userInfoOperationService.getUserId(username);
        if (userId != null) {
            UserLoginInfo userLoginInfo = userLoginInfoMapperDao.getUser(userId);
            long signDateTime = userLoginInfo.getSignDateTime();
            String salt = String.valueOf(signDateTime % 10000);
            String hashedPassword = HashUtils.saltHash(salt,password);
            if (hashedPassword.equals(userLoginInfo.getPassword())) {
                return userLoginInfo;
            }
        }
        return null;
    }

    public void resetUserLoginInfo(String username) {
        String userId = getUserId(username);
        UserLoginInfo userLoginInfo = getUser(userId);
        userLoginInfo.setIsVerified(1);
        long currentTime = System.currentTimeMillis();
        userLoginInfo.setSignDateTime(currentTime);
        String salt = String.valueOf(currentTime % 10000);
        String hashedPassword = HashUtils.saltHash(salt, userLoginInfo.getPassword());
        userLoginInfo.setPassword(hashedPassword);
        userLoginInfoMapperDao.updateUserLoginInfo(userLoginInfo);
    }

}

