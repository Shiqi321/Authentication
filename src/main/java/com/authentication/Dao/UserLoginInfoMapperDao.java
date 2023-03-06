package com.authentication.Dao;

import com.authentication.Model.UserLoginInfo;
import org.apache.ibatis.annotations.Param;



public interface UserLoginInfoMapperDao {

    String getUserId(@Param("username") String username);

    UserLoginInfo getUser(@Param("userId")String userId);

    UserLoginInfo insertUser(UserLoginInfo userLoginInfo);

    int getIsVerified(@Param("username")String username);

    void setIsVerified(@Param("username")String username);
}
