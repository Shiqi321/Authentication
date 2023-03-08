package com.authentication.Mapper;

import com.authentication.Model.EmailToken;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface EmailTokenMapper {

    EmailToken getExpiration(@Param("userId") String userId, @Param("token") String token);

    void insertEmailToken(EmailToken emailToken);
}
