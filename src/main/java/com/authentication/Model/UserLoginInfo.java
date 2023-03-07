package com.authentication.Model;


import lombok.*;

@Data
@Setter
@Getter
public class UserLoginInfo {

    private String userId;
    private String username;
    private String password;
    private long signDateTime;
    private int isVerified;
}
