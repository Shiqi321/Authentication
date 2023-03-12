package com.authentication.Model;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public enum TokenResponse {
    ExpirationResponse(0, "token is expired"),
    ChangedResponse(1, "token has been changed"),
    MatchResponse(2, "token is authenticated"),
    NotExistResponse(3, "token not exist"),
    TypeErrorResponse(4, "verify type error"),
    InforErrorResponse(5, "the basic token info is not correct");


    private int code;
    private String message;
    TokenResponse(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode()
    {
        return code;
    }

    public void setCode(int code)
    {
        this.code = code;
    }

    public String getMessage()
    {
        return message;
    }

    public void setMessage(String message)
    {
        this.message = message;
    }
}
