package com.authentication.Service;

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


@Service
public class EmailService {
    private final Logger logger = LoggerFactory.getLogger(EmailService.class);
    @Autowired
    private JavaMailSender mailSender;

    @Value("${message.mail.verification}")
    private String verfication;

    @Value("${spring.mail.username}")
    private String from;


    @Async
    public void sendVerificationEmail(String username, String token) throws MessagingException {
        sendEmail(verfication + "http://localhost:8080//verifyEmail?"+"username=" + username + "token=" +token,
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


}
