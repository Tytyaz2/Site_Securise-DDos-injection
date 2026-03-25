package com.app.security.validation;

import com.app.security.tableBDD.Note;
import com.app.security.tableBDD.User;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Bean Validation constraints on Note and User entities.
 *
 * Each constraint is tested with a violating value AND a valid boundary value,
 * so we confirm both that violations are caught AND that valid data passes.
 * No Spring context required.
 */
@DisplayName("Input Validation — Bean Validation constraints")
class InputValidationTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    // -----------------------------------------------------------------------
    // Note — title
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Note: blank title → @NotBlank violation")
    void note_blankTitle_violatesNotBlank() {
        Note note = validNote();
        note.setTitle("");
        assertViolated(validator.validate(note), "title");
    }

    @Test
    @DisplayName("Note: title > 200 chars → @Size violation")
    void note_titleTooLong_violatesSize() {
        Note note = validNote();
        note.setTitle("A".repeat(201));
        assertViolated(validator.validate(note), "title");
    }

    @Test
    @DisplayName("Note: title exactly 200 chars → no violation")
    void note_titleAt200Chars_passes() {
        Note note = validNote();
        note.setTitle("A".repeat(200));
        assertNoViolations(validator.validate(note));
    }

    // -----------------------------------------------------------------------
    // Note — content
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Note: blank content → @NotBlank violation")
    void note_blankContent_violatesNotBlank() {
        Note note = validNote();
        note.setContent("   ");
        assertViolated(validator.validate(note), "content");
    }

    @Test
    @DisplayName("Note: content > 10 000 chars → @Size violation")
    void note_contentTooLong_violatesSize() {
        Note note = validNote();
        note.setContent("X".repeat(10_001));
        assertViolated(validator.validate(note), "content");
    }

    @Test
    @DisplayName("Note: content exactly 10 000 chars → no violation")
    void note_contentAt10000Chars_passes() {
        Note note = validNote();
        note.setContent("X".repeat(10_000));
        assertNoViolations(validator.validate(note));
    }

    // -----------------------------------------------------------------------
    // User — username
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("User: blank username → @NotBlank violation")
    void user_blankUsername_violatesNotBlank() {
        User user = validUser();
        user.setUsername("");
        assertViolated(validator.validate(user), "username");
    }

    @Test
    @DisplayName("User: username shorter than 3 chars → @Size violation")
    void user_usernameTooShort_violatesSize() {
        User user = validUser();
        user.setUsername("ab");
        assertViolated(validator.validate(user), "username");
    }

    @Test
    @DisplayName("User: username longer than 50 chars → @Size violation")
    void user_usernameTooLong_violatesSize() {
        User user = validUser();
        user.setUsername("a".repeat(51));
        assertViolated(validator.validate(user), "username");
    }

    @Test
    @DisplayName("User: username with spaces → @Pattern violation (log-injection prevention)")
    void user_usernameWithSpaces_violatesPattern() {
        User user = validUser();
        user.setUsername("user name");
        assertViolated(validator.validate(user), "username");
    }

    @Test
    @DisplayName("User: username with semicolon → @Pattern violation (log-injection prevention)")
    void user_usernameWithSemicolon_violatesPattern() {
        User user = validUser();
        user.setUsername("user;DROP TABLE users;--");
        assertViolated(validator.validate(user), "username");
    }

    @Test
    @DisplayName("User: valid alphanumeric username with underscore → no violation")
    void user_validUsername_passes() {
        User user = validUser();
        user.setUsername("valid_user-123");
        assertNoViolations(validator.validate(user));
    }

    // -----------------------------------------------------------------------
    // User — password
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("User: blank password → @NotBlank violation")
    void user_blankPassword_violatesNotBlank() {
        User user = validUser();
        user.setPassword("");
        assertViolated(validator.validate(user), "password");
    }

    @Test
    @DisplayName("User: password > 100 chars → @Size violation (BCrypt DoS prevention)")
    void user_passwordTooLong_violatesSize() {
        User user = validUser();
        user.setPassword("P".repeat(101));
        assertViolated(validator.validate(user), "password");
    }

    @Test
    @DisplayName("User: password exactly 100 chars → no violation")
    void user_passwordAt100Chars_passes() {
        User user = validUser();
        user.setPassword("P".repeat(100));
        assertNoViolations(validator.validate(user));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private Note validNote() {
        Note note = new Note();
        note.setTitle("Valid title");
        note.setContent("Valid content");
        return note;
    }

    private User validUser() {
        User user = new User();
        user.setUsername("validuser");
        user.setPassword("validpassword");
        user.setRole("ROLE_USER");
        return user;
    }

    private <T> void assertViolated(Set<ConstraintViolation<T>> violations, String field) {
        assertThat(violations)
                .as("Expected a constraint violation on field '%s'", field)
                .anyMatch(v -> v.getPropertyPath().toString().equals(field));
    }

    private <T> void assertNoViolations(Set<ConstraintViolation<T>> violations) {
        assertThat(violations)
                .as("Expected no constraint violations but found: %s", violations)
                .isEmpty();
    }
}
