package com.authentication.Service;

import com.authentication.Mapper.EmailTokenMapper;
import com.authentication.Model.EmailToken;
import com.authentication.Model.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.UUID;


@Service
public class EmailService {
    private final Logger logger = LoggerFactory.getLogger(EmailService.class);
    @Autowired
    private JavaMailSender mailSender;

    @Value("${message.mail.verification}")
    private String verfication;

    @Value("${spring.mail.username}")
    private String from;

    @Value("${message.mail.expiration}")
    private long expiration;

    @Autowired
    private EmailTokenMapper emailTokenMapper;

    @Autowired
    private UserInfoOperationService userInfoOperationService;


    @Async
    public void sendVerificationEmail(String username, int type) throws MessagingException {
        String token = generateToken(username, type);
        sendEmail(verfication + "http://localhost:8080//verifyEmail?"+"username=" + username + "&token=" +token
                +"&type="+type,
                username);
    }

    public void sendEmail(String content, String username) throws MessagingException {
        MimeMessage mail = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mail, true, "UTF-8");
        helper.setFrom(from);
        helper.setTo(username);
        helper.setSubject("Verify the email address");
        helper.setText(content, true);
        mailSender.send(mail);
    }

    public String generateToken(String username, int type) {
        String userId = userInfoOperationService.getUserId(username);
        String tokenId = UUID.randomUUID().toString();
        String token = UUID.randomUUID().toString();
        long ddl = System.currentTimeMillis() + expiration * 1000L;
        emailTokenMapper.insertEmailToken(new EmailToken(tokenId, userId, token, ddl, type));
        return token;
    }

    public TokenResponse verifiedToken(String userId, String token, int type) {
        EmailToken emailToken = emailTokenMapper.getExpiration(userId, token);
        if (emailToken == null) {
            return TokenResponse.NotExistResponse;
        }
        if (emailToken.getType() != type) {
            return TokenResponse.TypeErrorResponse;
        }
        long currentTime = System.currentTimeMillis();
        if (emailToken.getExpiration() < currentTime) {
            return TokenResponse.ExpirationResponse;
        }
        return TokenResponse.MatchResponse;
    }

}
