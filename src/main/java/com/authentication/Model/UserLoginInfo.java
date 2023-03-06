package com.authentication.Model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserLoginInfo {

    private String userId;
    private String username;
    private String password;
    private long signDateTime;
    private boolean isVerified;
}
