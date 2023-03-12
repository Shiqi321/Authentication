package com.authentication.Service;


import com.authentication.Model.UserLoginInfo;
import com.authentication.Repository.UserLoginInfoRepository;
import com.authentication.Util.HashUtils;
import com.authentication.Util.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserInfoOperationService {
    @Autowired
    private UserInfoOperationService userInfoOperationService;

    @Autowired
    private RedisUtil redisUtil;

    @Autowired
    private UserLoginInfoRepository userLoginInfoRepository;


    public UserLoginInfo getUserById(String userId) {
        //UserLoginInfo userLoginInfo = userLoginInfoMapperDao.getUser(userId);
        Optional<UserLoginInfo> userLoginInfo = userLoginInfoRepository.findById(userId);
        return userLoginInfo.get();
    }

    public UserLoginInfo getUserByUsername(String username) {
        return userLoginInfoRepository.findByUsername(username);
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
        userLoginInfoRepository.save(userLoginInfo);
        return userLoginInfo;
    }

    public UserLoginInfo getMatched(String username, String password) {
        UserLoginInfo userLoginInfo = userLoginInfoRepository.findByUsername(username);
        if (userLoginInfo != null) {
            long signDateTime = userLoginInfo.getSignDateTime();
            String salt = String.valueOf(signDateTime % 10000);
            String hashedPassword = HashUtils.saltHash(salt,password);
            if (hashedPassword.equals(userLoginInfo.getPassword())) {
                return userLoginInfo;
            }
        }
        return null;
    }

//    public void resetUserLoginInfo(String username) {
//        String userId = getUserId(username);
//        UserLoginInfo userLoginInfo = userLoginInfoRepository.findById(userId);
//        userLoginInfo.setIsVerified(1);
//        long currentTime = System.currentTimeMillis();
//        userLoginInfo.setSignDateTime(currentTime);
//        String salt = String.valueOf(currentTime % 10000);
//        String hashedPassword = HashUtils.saltHash(salt, userLoginInfo.getPassword());
//        userLoginInfo.setPassword(hashedPassword);
//        userLoginInfoMapperDao.updateUserLoginInfo(userLoginInfo);
//    }

    public void blockUser(String userId, long time) {
        String key = "blocked";
        redisUtil.sSetAndTime(key, time, userId);
    }

    public long getLoginTimes(String userId) {
        String key = userId + "-" + "login_times";
        if (!redisUtil.hasKey(userId)) {
            redisUtil.set(key, 1, 60);
        }
        return redisUtil.incr(key, 1);
    }

    public void updateUser(UserLoginInfo userLoginInfo) {
        userLoginInfoRepository.save(userLoginInfo);

    }

}

