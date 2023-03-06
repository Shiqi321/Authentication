package com.authentication.Service;

import com.authentication.Dao.UserLoginInfoMapperDao;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Util.HashUtils;
import com.google.common.hash.Hashing;
import com.sun.org.apache.xml.internal.security.algorithms.implementations.SignatureDSA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.jws.soap.SOAPBinding;
import java.nio.charset.StandardCharsets;

@Service
public class AuthenticateUserService {
    @Autowired
    private UserLoginInfoMapperDao userLoginInfoMapperDao;
    @Autowired
    private UserInfoOperationService userInfoOperationService;

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

}
