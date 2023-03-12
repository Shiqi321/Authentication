package com.authentication.Model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "EmailToken", schema = "JWT")
public class EmailToken {
    @Id
    private String tokenId;
    private String userId;
    private String token;
    private long expiration;
    private int type;
}
