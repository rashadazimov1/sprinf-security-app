package com.company.security.service;

import com.company.security.model.Role;
import com.company.security.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    @Autowired
    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    /**
     *Verilənlər bazasından bütün rolları tapır
     */
    public Collection<Role> findAll() {
        return roleRepository.findAll();
    }

}
