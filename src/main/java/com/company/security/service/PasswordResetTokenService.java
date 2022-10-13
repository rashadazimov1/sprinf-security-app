package com.company.security.service;


import com.company.security.exception.InvalidTokenRequestException;
import com.company.security.exception.ResourceNotFoundException;
import com.company.security.model.PasswordResetToken;
import com.company.security.model.User;
import com.company.security.model.payload.PasswordResetRequest;
import com.company.security.repository.PasswordResetTokenRepository;
import com.company.security.util.Util;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository repository;

    @Value("${app.token.password.reset.duration}")
    private Long expiration;

    @Autowired
    public PasswordResetTokenService(PasswordResetTokenRepository repository) {
        this.repository = repository;
    }

    /**
     *NaturalId verilmiş verilənlər bazasında tokeni tapır və ya exception atır.
     * reset token istifadəçinin e-poçtuna uyğun olmalıdır və yenidən istifadə edilə bilməz
     */
    public PasswordResetToken getValidToken(PasswordResetRequest request) {
        String tokenID = request.getToken();
        PasswordResetToken token = repository.findByToken(tokenID)
                .orElseThrow(() -> new ResourceNotFoundException("Password Reset Token", "Token Id", tokenID));

        matchEmail(token, request.getEmail());
        verifyExpiration(token);
        return token;
    }

    /**
     * İstifadəçinin sahib olmalı olduğu yeni parol tokeni yaradır və qaytarır
     * associated and persists in the token repository.
     */
    public Optional<PasswordResetToken> createToken(User user) {
        PasswordResetToken token = createTokenWithUser(user);
        return Optional.of(repository.save(token));
    }

    /**
     * İstifadəçi parol tələb edə bildiyi üçün birdən çox tokenler
     * yaradılacaq. Buna görə də bütün mövcud parolları silməliyik.
     * İstifadəçi parolunu dəyişdirmə tokenleri sıfırlayın.
     */
    public PasswordResetToken claimToken(PasswordResetToken token) {
        User user = token.getUser();
        token.setClaimed(true);

        CollectionUtils.emptyIfNull(repository.findActiveTokensForUser(user))
                .forEach(t -> t.setActive(false));

        return token;
    }

    /**
     * Təqdim olunan tokenin  hazrki statusa əsasən müddətinin bitib-keçmədiyini yoxlayın.
     */
    void verifyExpiration(PasswordResetToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            throw new InvalidTokenRequestException("Password Reset Token", token.getToken(),
                    "Expired token. Please issue a new request");
        }
        if (!token.getActive()) {
            throw new InvalidTokenRequestException("Password Reset Token", token.getToken(),
                    "Token was marked inactive");
        }
    }

    /**
     *  Təqdim olunan token həqiqətən istifadəçi tərəfindən yaradılıbsa, uyğun gəlir
     */
    void matchEmail(PasswordResetToken token, String requestEmail) {
        if (token.getUser().getEmail().compareToIgnoreCase(requestEmail) != 0) {
            throw new InvalidTokenRequestException("Password Reset Token", token.getToken(),
                    "Token is invalid for the given user " + requestEmail);
        }
    }

    PasswordResetToken createTokenWithUser(User user) {
        String tokenID = Util.generateRandomUuid();
        PasswordResetToken token = new PasswordResetToken();
        token.setToken(tokenID);
        token.setExpiryDate(Instant.now().plusMillis(expiration));
        token.setClaimed(false);
        token.setActive(true);
        token.setUser(user);
        return token;
    }
}
