package com.authentication.Service;

import com.authentication.Model.EmailToken;
import com.authentication.Model.TokenResponse;
import com.authentication.Model.UserLoginInfo;
import com.authentication.Repository.EmailTokenRepository;
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
    private EmailTokenRepository emailTokenRepository;

    @Autowired
    private UserInfoOperationService userInfoOperationService;


    @Async
    public void sendVerificationEmail(String userId, String username, int type) throws MessagingException {
        String token = generateToken(userId, type);
        sendEmail(verfication + "http://localhost:8080//verifyEmail?"+"userId=" + userId + "&token=" +token
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

    public String generateToken(String userId, int type) {
        String tokenId = UUID.randomUUID().toString();
        String token = UUID.randomUUID().toString();
        long ddl = System.currentTimeMillis() + expiration * 1000L;
        emailTokenRepository.save(new EmailToken(tokenId, userId, token, ddl, type));
        return token;
    }

    public TokenResponse verifiedToken(String userId, String token, int type) {

        EmailToken emailToken = emailTokenRepository.findByUserId(userId);
        if (emailToken == null) {
            return TokenResponse.NotExistResponse;
        }
        if (!emailToken.getToken().equals(token)) {
            return TokenResponse.ChangedResponse;
        }
        if (emailToken.getType() != type) {
            return TokenResponse.TypeErrorResponse;
        }
        long currentTime = System.currentTimeMillis();
        if (emailToken.getExpiration() < currentTime) {
            return TokenResponse.ExpirationResponse;
        }
        emailTokenRepository.delete(emailToken);
        return TokenResponse.MatchResponse;
    }

}
