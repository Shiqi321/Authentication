package com.authentication.Service;


import com.authentication.Model.UserLoginInfo;
import com.authentication.Repository.UserLoginInfoRepository;
import com.authentication.Util.Utils;
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
        userLoginInfo.setIsDeleted(0);
        userLoginInfo.setLastUpdateTime(currentTime);
        String salt = String.valueOf(currentTime % 10000);
        String hashedPassword = Utils.saltHash(salt, userLoginInfo.getPassword());
        userLoginInfo.setPassword(hashedPassword);
        userLoginInfoRepository.save(userLoginInfo);
        return userLoginInfo;
    }

    public boolean getMatched(String username, String password) {
        UserLoginInfo userLoginInfo = userLoginInfoRepository.findByUsername(username);
        if (userLoginInfo != null) {
            long signDateTime = userLoginInfo.getSignDateTime();
            String salt = String.valueOf(signDateTime % 10000);
            String hashedPassword = Utils.saltHash(salt,password);
            if (hashedPassword.equals(userLoginInfo.getPassword())) {
                return true;
            }
        }
        return false;
    }

    public long getLoginTimes(String userId) {
        String key = userId + "-" + "login_times";
        if (!redisUtil.hasKey(userId)) {
            redisUtil.set(key, 1, 60);
        }
        return redisUtil.incr(key, 1);
    }

    public void updateUser(UserLoginInfo userLoginInfo) {
        userLoginInfo.setLastUpdateTime(System.currentTimeMillis());
        userLoginInfoRepository.save(userLoginInfo);

    }

}

