package com.company.security.service;


import com.company.security.exception.InvalidTokenRequestException;
import com.company.security.model.TokenStatus;
import com.company.security.model.User;
import com.company.security.model.token.EmailVerificationToken;
import com.company.security.repository.EmailVerificationTokenRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class EmailVerificationTokenService {

    private static final Logger logger = Logger.getLogger(EmailVerificationTokenService.class);
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Value("${app.token.email.verification.duration}")
    private Long emailVerificationTokenExpiryDuration;

    @Autowired
    public EmailVerificationTokenService(EmailVerificationTokenRepository emailVerificationTokenRepository) {
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
    }

    /**
     *E-poçt doğrulama  tokeni yaradın və onu olacaq verilənlər bazasında saxlayın
     *istifadəçi tərəfindən təsdiq edilmişdir
     */
    public void createVerificationToken(User user, String token) {
        EmailVerificationToken emailVerificationToken = new EmailVerificationToken();
        emailVerificationToken.setToken(token);
        emailVerificationToken.setTokenStatus(TokenStatus.STATUS_PENDING);
        emailVerificationToken.setUser(user);
        emailVerificationToken.setExpiryDate(Instant.now().plusMillis(emailVerificationTokenExpiryDuration));
        logger.info("Generated Email verification token [" + emailVerificationToken + "]");
        emailVerificationTokenRepository.save(emailVerificationToken);
    }

    /**
     * Verilənlər bazasındakı mövcud tokeni yeni müddəti ilə yeniləyir
     */
    public EmailVerificationToken updateExistingTokenWithNameAndExpiry(EmailVerificationToken existingToken) {
        existingToken.setTokenStatus(TokenStatus.STATUS_PENDING);
        existingToken.setExpiryDate(Instant.now().plusMillis(emailVerificationTokenExpiryDuration));
        logger.info("Updated Email verification token [" + existingToken + "]");
        return save(existingToken);
    }

    /**
     * @NaturalId işarəsi ilə e-poçt doğrulama tokeni tapır
     */
    public Optional<EmailVerificationToken> findByToken(String token) {
        return emailVerificationTokenRepository.findByToken(token);
    }


    public EmailVerificationToken save(EmailVerificationToken emailVerificationToken) {
        return emailVerificationTokenRepository.save(emailVerificationToken);
    }

    /**
     * E-poçtun yoxlanılması üçün token kimi istifadə edilmək üçün yeni təsadüfi UUID yaradır
     */
    public String generateNewToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Təqdim olunan tokenin istifadə müddətini keçib-keçmədiyini movcud əsasında yoxlayır
     * server vaxtı və/və ya başqa cür səhv atmaq
     */
    public void verifyExpiration(EmailVerificationToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            throw new InvalidTokenRequestException("Email Verification Token", token.getToken(), "Expired token. Please issue a new request");
        }
    }

}
