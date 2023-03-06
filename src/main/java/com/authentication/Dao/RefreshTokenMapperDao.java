package com.authentication.Dao;


import com.authentication.Model.RefreshToken;
import com.authentication.Model.RefreshTokenFamily;

public interface RefreshTokenMapperDao {


    int getIsUsed(String refreshToken);

    String getFamilyTokenId(String refreshToken);

    void setIsUsed(int isUsed, String refreshId);

    void setIsUsedByFamilyId(int isUsed, String familyId);

    void insertRefreshToken(RefreshToken refreshToken);

    void insertFamilyRefreshToken(RefreshTokenFamily refreshTokenFamily);

    String getRefreshId(String refreshToken);
}
