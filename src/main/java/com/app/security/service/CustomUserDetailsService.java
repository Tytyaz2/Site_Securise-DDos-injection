package com.app.security.service;

import com.app.security.tableBDD.User;
import com.app.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Loads user details from the database for Spring Security authentication.
 *
 * SECURITY: Login attempts are logged at DEBUG level only so usernames are
 * not written to production log files at INFO/WARN level.  Failed lookups
 * still throw {@link UsernameNotFoundException} — Spring Security normalises
 * the timing response to prevent user-enumeration via response-time
 * differences.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DEBUG so username is not written in production logs (where level is INFO+)
        log.debug("Authentication attempt for user: {}", username);

        User user = userRepository.findByUsername(username);

        if (user == null) {
            // Do NOT log the missing username at WARN/INFO — avoids user-enumeration via logs
            log.debug("User not found in database");
            throw new UsernameNotFoundException("Bad credentials");
        }

        log.debug("User found, building UserDetails");
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole()))
        );
    }
}
