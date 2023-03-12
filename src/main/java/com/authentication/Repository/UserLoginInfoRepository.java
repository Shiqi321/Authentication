package com.authentication.Repository;

import com.authentication.Model.UserLoginInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserLoginInfoRepository extends JpaRepository<UserLoginInfo, String>, CrudRepository<UserLoginInfo, String> {

    //UserLoginInfo findById(String userId);

    UserLoginInfo findByUsername(String username);

    UserLoginInfo save(UserLoginInfo userLoginInfo);

}
