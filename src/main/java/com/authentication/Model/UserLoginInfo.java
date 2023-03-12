package com.authentication.Model;


import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Data
@Setter
@Getter
@Entity
@Table(name = "UserLoginInfo", schema = "JWT")
public class UserLoginInfo {
    @Id
    @Column(name = "userId")
    private String userId;
    @Column(name = "username")
    private String username;
    @Column(name = "password")
    private String password;
    @Column(name = "signDateTime")
    private long signDateTime;
    @Column(name = "isVerified")
    private int isVerified;
    @Column
    private long lastUpdateTime;
    @Column
    private int isDeleted;
}
