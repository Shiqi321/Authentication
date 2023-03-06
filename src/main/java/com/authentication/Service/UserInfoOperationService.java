package com.authentication.Service;

import com.authentication.Dao.UserLoginInfoMapperDao;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Util.HashUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserInfoOperationService {
    @Autowired
    private UserLoginInfoMapperDao userLoginInfoMapperDao;
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

    public void insertNewUser(UserLoginInfo userLoginInfo) {
        userLoginInfo.setVerified(false);
        long currentTime = System.currentTimeMillis();
        String salt = String.valueOf(currentTime % 10000);
        String hashedPassword = HashUtils.saltHash(salt, userLoginInfo.getPassword());
        userLoginInfo.setPassword(hashedPassword);
        userLoginInfoMapperDao.insertUser(userLoginInfo);
    }

    public void verifiedEmail(String username) {
        userLoginInfoMapperDao.setIsVerified(username);
    }


}

