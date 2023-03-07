package com.authentication.Mapper;


import com.authentication.Model.RefreshToken;
import com.authentication.Model.RefreshTokenFamily;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface RefreshTokenMapper {


    int getIsUsed(String refreshTokenId);

    String getFamilyTokenId(String refreshTokenId);

    void setIsUsed(int isUsed, String refreshId);

    void setIsUsedByFamilyId(int isUsed, String familyId);

    void insertRefreshToken(RefreshToken refreshToken);

    void insertFamilyRefreshToken(RefreshTokenFamily refreshTokenFamily);

    String getRefreshId(String refreshToken);
}
