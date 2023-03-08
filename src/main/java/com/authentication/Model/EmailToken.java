package com.authentication.Model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailToken {
    private String tokenId;
    private String userId;
    private String token;
    private long expiration;
    private int type;
}
