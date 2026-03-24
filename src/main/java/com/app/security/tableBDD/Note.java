package com.app.security.tableBDD;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Persistent note entity.
 *
 * SECURITY: Bean Validation constraints prevent excessively large or blank
 * values from reaching the database layer.  The service layer must call
 * validation explicitly (or use @Validated on the service) because JPA does
 * not validate by default before flush unless the validator is registered.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Le titre ne peut pas être vide")
    @Size(min = 1, max = 200, message = "Le titre doit contenir entre 1 et 200 caractères")
    @Column(nullable = false, length = 200)
    private String title;

    @NotBlank(message = "Le contenu ne peut pas être vide")
    @Size(min = 1, max = 10000, message = "Le contenu doit contenir entre 1 et 10 000 caractères")
    @Column(nullable = false, length = 10000)
    private String content;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
