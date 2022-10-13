package com.company.security.service;

import com.company.security.annotation.CurrentUser;
import com.company.security.exception.UserLogoutException;
import com.company.security.model.CustomUserDetails;
import com.company.security.model.Role;
import com.company.security.model.User;
import com.company.security.model.UserDevice;
import com.company.security.model.payload.LogOutRequest;
import com.company.security.model.payload.RegistrationRequest;
import com.company.security.repository.UserRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    private static final Logger logger = Logger.getLogger(UserService.class);
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleService roleService;
    private final UserDeviceService userDeviceService;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository, RoleService roleService, UserDeviceService userDeviceService, RefreshTokenService refreshTokenService) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.roleService = roleService;
        this.userDeviceService = userDeviceService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * metod Verilənlər bazasında istifadəçi adı tapr
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * E-poçt vasitəsilə verilənlər bazasında istifadəçi tapır
     */
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * İd ilə db-də istifadəçi tapır.
     */
    public Optional<User> findById(Long Id) {
        return userRepository.findById(Id);
    }

    /**
     * İstifadəçini verilənlər bazasında saxlayr
     */
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * E-poçtla istifadəçinin mövcud olduğunu yoxlayır: naturalId
     */
    public Boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * İstifadəçi adı ilə istifadəçinin olub olmadığını yoxlayır: naturalId
     */
    public Boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }


    /**
     * Qeydiyyat sorğusundan yeni istifadəçi yaradır
     */
    public User createUser(RegistrationRequest registerRequest) {
        User newUser = new User();
        Boolean isNewUserAsAdmin = registerRequest.getRegisterAsAdmin();
        newUser.setEmail(registerRequest.getEmail());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setUsername(registerRequest.getUsername());
        newUser.addRoles(getRolesForNewUser(isNewUserAsAdmin));
        newUser.setActive(true);
        newUser.setEmailVerified(false);
        return newUser;
    }

    /**
     * Yeni istifadəçinin hansı rollara təyin oluna biləcəyini görmək üçün sürətli yoxlama həyata keçirir.
     *
     * yeni istifadəçi üçün rolların siyahısını qaytarır
     */
    private Set<Role> getRolesForNewUser(Boolean isToBeMadeAdmin) {
        Set<Role> newUserRoles = new HashSet<>(roleService.findAll());
        if (!isToBeMadeAdmin) {
            newUserRoles.removeIf(Role::isAdminRole);
        }
        logger.info("İstifadəçi rollarının təyin edilməsi: " + newUserRoles);
        return newUserRoles;
    }

    /**
     * Verilmiş istifadəçidən çıxır və onunla əlaqəli yeniləmə tokenini silir. Cihaz yoxdursa
     * id bu istifadəçi üçün verilənlər bazasına uyğun gəlirse, çıxış exteption atır.
     */
    public void logoutUser(@CurrentUser CustomUserDetails currentUser, LogOutRequest logOutRequest) {
        String deviceId = logOutRequest.getDeviceInfo().getDeviceId();
        UserDevice userDevice = userDeviceService.findDeviceByUserId(currentUser.getId(), deviceId)
                .filter(device -> device.getDeviceId().equals(deviceId))
                .orElseThrow(() -> new UserLogoutException(logOutRequest.getDeviceInfo().getDeviceId(), "Yanlış cihaz İD təqdim edilib. Verilmiş istifadəçi üçün uyğun cihaz tapılmadı "));

        logger.info("Cihazla əlaqəli yeniləmə tokeni silinir [" + userDevice + "]");
        refreshTokenService.deleteById(userDevice.getRefreshToken().getId());
    }
}
