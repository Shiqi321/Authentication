package com.authentication.Repository;

import com.authentication.Model.EmailToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

public interface EmailTokenRepository extends JpaRepository<EmailToken, String>, CrudRepository<EmailToken, String> {
    EmailToken findByUserId(String userId);
}
