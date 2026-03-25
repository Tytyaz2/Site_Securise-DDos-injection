package com.app.security;

import com.app.TestConfig;
import com.app.security.repository.NoteRepository;
import com.app.security.repository.UserRepository;
import com.app.security.tableBDD.Note;
import com.app.security.tableBDD.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies authentication enforcement and IDOR (Insecure Direct Object Reference) prevention.
 *
 * IDOR scenario: user "attacker" attempts to read or edit a note belonging to "owner".
 * The application must silently redirect to /home without exposing the note content.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("Access Control & IDOR Prevention")
class AccessControlTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Long ownerNoteId;

    @BeforeEach
    void seedDatabase() {
        // Clean slate before each test to avoid leftover data
        noteRepository.deleteAll();
        // Keep the admin user created by DataLoader; only delete test users
        User existingOwner = userRepository.findByUsername("owner");
        if (existingOwner != null) {
            userRepository.delete(existingOwner);
        }
        User existingAttacker = userRepository.findByUsername("attacker");
        if (existingAttacker != null) {
            userRepository.delete(existingAttacker);
        }

        User owner = new User(null, "owner",
                passwordEncoder.encode("ownerPass"), "ROLE_USER");
        userRepository.save(owner);

        User attacker = new User(null, "attacker",
                passwordEncoder.encode("attackerPass"), "ROLE_USER");
        userRepository.save(attacker);

        Note note = new Note(null, "Owner's Secret", "Private content", owner, null);
        Note saved = noteRepository.save(note);
        ownerNoteId = saved.getId();
    }

    @AfterEach
    void cleanup() {
        noteRepository.deleteAll();
        User owner = userRepository.findByUsername("owner");
        if (owner != null) userRepository.delete(owner);
        User attacker = userRepository.findByUsername("attacker");
        if (attacker != null) userRepository.delete(attacker);
    }

    // -----------------------------------------------------------------------
    // Authentication enforcement
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /home without authentication → redirect to /login")
    void getHome_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login*"));
    }

    @Test
    @DisplayName("GET /home/note/{id} without authentication → redirect to /login")
    void getNoteForm_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/home/note/" + ownerNoteId))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login*"));
    }

    @Test
    @DisplayName("POST /home/add without authentication → redirect to /login")
    void postAddNote_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(post("/home/add")
                        .with(csrf())
                        .param("title", "test")
                        .param("content", "content"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login*"));
    }

    // -----------------------------------------------------------------------
    // IDOR — read another user's note
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(username = "attacker")
    @DisplayName("IDOR: GET /home/note/{id} owned by another user → redirect to /home, not 200")
    void getNoteForm_asWrongUser_redirectsToHome() throws Exception {
        mockMvc.perform(get("/home/note/" + ownerNoteId))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/home"));
    }

    // -----------------------------------------------------------------------
    // IDOR — edit another user's note
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(username = "attacker")
    @DisplayName("IDOR: POST /notes/{id}/edit owned by another user → redirect to /home, not saved")
    void postNoteEdit_asWrongUser_redirectsToHome() throws Exception {
        mockMvc.perform(post("/notes/" + ownerNoteId + "/edit")
                        .with(csrf())
                        .param("title", "Hacked title")
                        .param("content", "Hacked content"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/home"));

        // Verify the note content was NOT modified
        Note note = noteRepository.findById(ownerNoteId).orElseThrow();
        assert note.getTitle().equals("Owner's Secret") : "Note title must not be changed by attacker";
    }

    // -----------------------------------------------------------------------
    // Legitimate access (owner can read and edit their own note)
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(username = "owner")
    @DisplayName("GET /home/note/{id} as owner → 200 OK")
    void getNoteForm_asOwner_returns200() throws Exception {
        mockMvc.perform(get("/home/note/" + ownerNoteId))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "owner")
    @DisplayName("POST /notes/{id}/edit as owner → redirect to note page (save successful)")
    void postNoteEdit_asOwner_savesAndRedirects() throws Exception {
        mockMvc.perform(post("/notes/" + ownerNoteId + "/edit")
                        .with(csrf())
                        .param("title", "Updated title")
                        .param("content", "Updated content"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/home/note/" + ownerNoteId));

        Note note = noteRepository.findById(ownerNoteId).orElseThrow();
        assert note.getTitle().equals("Updated title") : "Note title should be updated by owner";
    }
}
