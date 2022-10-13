package com.company.security.service;

import com.company.security.exception.TokenRefreshException;
import com.company.security.model.token.RefreshToken;
import com.company.security.repository.RefreshTokenRepository;
import com.company.security.util.Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.token.refresh.duration}")
    private Long refreshTokenDurationMs;

    @Autowired
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * tokenin  özünə əsaslanan refresh tokeni tapır
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Yenilənmiş refreshTokeni verilənlər bazasında saxlayır
     */
    public RefreshToken save(RefreshToken refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * yaradılmış Yeni  refresh token  qaytarır
     */
    public RefreshToken createRefreshToken() {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(Util.generateRandomUuid());
        refreshToken.setRefreshCount(0L);
        return refreshToken;
    }

    /**
     * Təqdim olunan tokenin istifadə müddətini keçib-keçmədiyini  yoxlayır
     *
     */
    public void verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            throw new TokenRefreshException(token.getToken(), "Müddəti bitmiş token. Zəhmət olmasa yeni sorğu göndərin");
        }
    }

    /**
     * İstifadəçi cihazı ilə əlaqəli yeniləmə tokenini silir
     */
    public void deleteById(Long id) {
        refreshTokenRepository.deleteById(id);
    }

    /**
     *Verilənlər bazasında token istifadəsinin sayını artırır.
     * audit məqsədləri üçün faydalıdır
     */
    public void increaseCount(RefreshToken refreshToken) {
        refreshToken.incrementRefreshCount();
        save(refreshToken);
    }
}
