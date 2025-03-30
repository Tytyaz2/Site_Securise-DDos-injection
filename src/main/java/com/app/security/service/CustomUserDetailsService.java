// File: src/main/java/com/app/security/service/CustomUserDetailsService.java
package com.app.security.service;

import com.app.security.tableBDD.User;
import com.app.security.repository.UserRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Tentative de connexion avec l'utilisateur : " + username);

        User user = userRepository.findByUsername(username);
        if (user == null) {
            System.out.println("Utilisateur non trouvé : " + username);
            throw new UsernameNotFoundException("Utilisateur non trouvé : " + username);
        }

        System.out.println("Utilisateur trouvé : " + user.getUsername());
        System.out.println("Mot de passe enregistré : " + user.getPassword());
        System.out.println("Rôle brut : " + user.getRole());

        String role = user.getRole();
        if (!role.startsWith("ROLE_")) {
            role = "ROLE_" + role.toUpperCase();
        }
        System.out.println("Autorité retournée à Spring Security : " + role);

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(role))
        );
    }
}
