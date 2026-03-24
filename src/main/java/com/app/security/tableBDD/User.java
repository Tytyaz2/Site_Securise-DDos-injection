package com.app.security.tableBDD;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Persistent user entity implementing Spring Security's {@link UserDetails}.
 *
 * SECURITY:
 * - Username is constrained to alphanumeric + underscore/hyphen characters to
 *   prevent injection of control characters into log files (log injection) and
 *   reduce the risk of unexpected behaviour in downstream systems.
 * - Password length is bounded to prevent denial-of-service via BCrypt on
 *   extremely long inputs (BCrypt itself caps at 72 bytes; bounding earlier
 *   provides a clear application-level contract).
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Le nom d'utilisateur ne peut pas être vide")
    @Size(min = 3, max = 50, message = "Le nom d'utilisateur doit contenir entre 3 et 50 caractères")
    @Pattern(
        regexp = "^[a-zA-Z0-9_-]+$",
        message = "Le nom d'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores"
    )
    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @NotBlank(message = "Le mot de passe ne peut pas être vide")
    @Size(max = 100, message = "Le mot de passe ne doit pas dépasser 100 caractères")
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role; // e.g. "ROLE_USER", "ROLE_ADMIN"

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
