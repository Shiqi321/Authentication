package com.authentication.Mapper;

import com.authentication.Model.UserLoginInfo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;


@Mapper
public interface UserLoginInfoMapper {

    String getUserId(@Param("username") String username);

    UserLoginInfo getUser(@Param("userId")String userId);

    void insertUser(UserLoginInfo userLoginInfo);

    int getIsVerified(@Param("username")String username);

    void setIsVerified(@Param("isVerified") int isVerified, @Param("username")String username);

    void updateUserLoginInfo(UserLoginInfo userLoginInfo);
}
