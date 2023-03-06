package com.authentication.Model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@NoArgsConstructor
public enum Error {
    UserNameException(-1, "username does not exist"),
    MatchedException(-2, "username and password are not matched"),
    ExpirationException(-3, "token is expired"),
    ReautheticationException(-4, "please relogin"),
    TokenException(-5, "the token is not authenticated"),
    VerifiedException(-6, "the email is not verified"),
    ExistException(-7, "this email has an account");

    private int code;
    private String message;

    public int getCode()
    {
        return code;
    }


    public String getErrMsg()
    {
        return message;
    }

    Error(int code, String errMsg)
    {
        this.code = code;
        this.message = errMsg;
    }

}
