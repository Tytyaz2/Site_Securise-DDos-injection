package com.app.controller;

import com.app.security.tableBDD.Note;
import com.app.security.repository.NoteRepository;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

/**
 * Handles note update operations.
 *
 * SECURITY:
 * - Ownership is verified against the authenticated principal, not a request
 *   parameter, preventing IDOR (Insecure Direct Object Reference) attacks.
 * - Input length is bounded to match the database column constraints.
 * - The redirect after save now points to the existing /home/note/{id} route
 *   (the original /notes/{id} route did not exist, causing a 404/redirect loop).
 * - Uses SLF4J for logging; raw user-supplied content is never logged.
 */
@Controller
@Validated
public class NoteController {

    private static final Logger log = LoggerFactory.getLogger(NoteController.class);

    private static final int MAX_TITLE_LENGTH = 200;
    private static final int MAX_CONTENT_LENGTH = 10000;

    private final NoteRepository noteRepository;

    public NoteController(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    @PostMapping("/notes/{id}/edit")
    public String updateNote(
            @PathVariable Long id,
            @RequestParam @NotBlank @Size(min = 1, max = MAX_TITLE_LENGTH) String title,
            @RequestParam @NotBlank @Size(min = 1, max = MAX_CONTENT_LENGTH) String content,
            Principal principal) {

        if (principal == null) {
            return "redirect:/login";
        }

        String username = principal.getName();

        Note note = noteRepository.findById(id)
                .orElse(null);

        if (note == null) {
            log.warn("Note update attempt on non-existent note={} by user={}", id, username);
            return "redirect:/home";
        }

        // SECURITY: enforce ownership — a user must not be able to edit another's note
        if (!note.getUser().getUsername().equals(username)) {
            log.warn("Unauthorized note update attempt: user={} tried to edit note={}", username, id);
            return "redirect:/home";
        }

        // Extra server-side size guard (mirrors @Size, defends against bypassed bean validation)
        if (title.length() > MAX_TITLE_LENGTH || content.length() > MAX_CONTENT_LENGTH) {
            log.warn("Note update rejected: input exceeds maximum size for note={} user={}", id, username);
            return "redirect:/home/note/" + id;
        }

        note.setTitle(title);
        note.setContent(content);
        noteRepository.save(note);

        log.info("Note updated: note={} user={}", id, username);

        // SECURITY: redirect to the correct existing route (was /notes/{id} which does not exist)
        return "redirect:/home/note/" + id;
    }
}
