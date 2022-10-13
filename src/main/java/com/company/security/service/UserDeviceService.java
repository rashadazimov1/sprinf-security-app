package com.company.security.service;


import com.company.security.exception.TokenRefreshException;
import com.company.security.model.UserDevice;
import com.company.security.model.payload.DeviceInfo;
import com.company.security.model.token.RefreshToken;
import com.company.security.repository.UserDeviceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDeviceService {

    private final UserDeviceRepository userDeviceRepository;

    @Autowired
    public UserDeviceService(UserDeviceRepository userDeviceRepository) {
        this.userDeviceRepository = userDeviceRepository;
    }

    /**
     * İstifadəçi id  ilə istifadəçi cihazı məlumatını tapır android ve yaxud ios
     */
    public Optional<UserDevice> findDeviceByUserId(Long userId, String deviceId) {
        return userDeviceRepository.findByUserIdAndDeviceId(userId, deviceId);
    }

    /**
     * Yeniləmə token ilə istifadəçi cihazı məlumatını tapır
     */
    public Optional<UserDevice> findByRefreshToken(RefreshToken refreshToken) {
        return userDeviceRepository.findByRefreshToken(refreshToken);
    }

    /**
     * Yeni istifadəçi cihazı yaradır və istifadəçini cari cihaza təyin edir
     */
    public UserDevice createUserDevice(DeviceInfo deviceInfo) {
        UserDevice userDevice = new UserDevice();
        userDevice.setDeviceId(deviceInfo.getDeviceId());
        userDevice.setDeviceType(deviceInfo.getDeviceType());
        userDevice.setNotificationToken(deviceInfo.getNotificationToken());
        userDevice.setRefreshActive(true);
        return userDevice;
    }

    /**
     * Tokenə uyğun istifadəçi cihazında yeniləmənin aktiv olub olmadığını yoxlayır və
     *        * Müştəriyə müvafiq səhvlər atmaq
     */
    void verifyRefreshAvailability(RefreshToken refreshToken) {
        UserDevice userDevice = findByRefreshToken(refreshToken)
                .orElseThrow(() -> new TokenRefreshException(refreshToken.getToken(), "Uyğun token üçün heç bir cihaz tapılmadı. Zəhmət olmasa yenidən daxil olun"));

        if (!userDevice.getRefreshActive()) {
            throw new TokenRefreshException(refreshToken.getToken(), "Yeniləmə cihaz üçün bloklanıb. Fərqli cihaz vasitəsilə daxil olun");
        }
    }
}
