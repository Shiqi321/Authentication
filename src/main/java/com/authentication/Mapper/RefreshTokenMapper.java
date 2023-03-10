package com.authentication.Mapper;


import com.authentication.Model.RefreshToken;
import com.authentication.Model.RefreshTokenFamily;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface RefreshTokenMapper {


    int getIsUsed(String refreshTokenId);

    String getFamilyTokenId(String refreshTokenId);

    void setIsUsed(@Param("isUsed") int isUsed, @Param("refreshTokenId") String refreshId);

    void setIsUsedByFamilyId(int isUsed, String familyId);

    void insertRefreshToken(RefreshToken refreshToken);

    void insertFamilyRefreshToken(RefreshTokenFamily refreshTokenFamily);

    String getRefreshId(String refreshToken);
}
