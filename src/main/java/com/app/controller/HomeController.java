package com.app.controller;

import com.app.security.service.NoteService;
import com.app.security.service.UserService;
import com.app.security.tableBDD.Note;
import com.app.security.tableBDD.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.List;

/**
 * Controller for the home page and note creation.
 *
 * SECURITY:
 * - All note inputs are validated for length/blank before reaching the service.
 * - The authenticated user is always resolved from the security principal, not
 *   from a request parameter, preventing IDOR on note creation.
 * - Uses SLF4J for logging; never logs raw user-supplied content.
 */
@Controller
@Validated
public class HomeController {

    private static final Logger log = LoggerFactory.getLogger(HomeController.class);

    // Maximum sizes mirroring the @Size constraints on Note entity
    private static final int MAX_TITLE_LENGTH = 200;
    private static final int MAX_CONTENT_LENGTH = 10000;

    private final NoteService noteService;
    private final UserService userService;

    public HomeController(NoteService noteService, UserService userService) {
        this.noteService = noteService;
        this.userService = userService;
    }

    @GetMapping("/home")
    public String home(Principal principal, Model model) {
        if (principal == null) {
            return "redirect:/login";
        }

        User user = userService.findByUsername(principal.getName());
        if (user == null) {
            return "redirect:/login";
        }

        List<Note> notes = noteService.getNotesByUser(user);
        model.addAttribute("notes", notes);
        return "home";
    }

    @PostMapping("/home/add")
    public String addNote(
            @RequestParam @NotBlank @Size(min = 1, max = MAX_TITLE_LENGTH) String title,
            @RequestParam @NotBlank @Size(min = 1, max = MAX_CONTENT_LENGTH) String content,
            Principal principal,
            RedirectAttributes redirectAttributes) {

        if (principal == null) {
            return "redirect:/login";
        }

        // Validate sizes explicitly at controller level as an extra layer of defence
        if (title.length() > MAX_TITLE_LENGTH || content.length() > MAX_CONTENT_LENGTH) {
            log.warn("Note creation rejected: input exceeds maximum allowed size for user={}",
                    principal.getName());
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Le titre ou le contenu dépasse la taille maximale autorisée.");
            return "redirect:/home";
        }

        User user = userService.findByUsername(principal.getName());
        if (user == null) {
            return "redirect:/login";
        }

        noteService.createNote(title, content, user);
        log.info("Note created by user={}", principal.getName());
        redirectAttributes.addFlashAttribute("message", "Note ajoutée avec succès !");
        return "redirect:/home";
    }

    @GetMapping("/home/note/{id}")
    public String editNoteForm(@PathVariable Long id, Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        Note note = noteService.getNoteById(id);
        if (note == null) {
            return "redirect:/home";
        }

        // SECURITY: enforce ownership — never expose another user's note
        if (!note.getUser().getUsername().equals(principal.getName())) {
            log.warn("Unauthorized note access attempt: user={} tried to access note={}",
                    principal.getName(), id);
            return "redirect:/home";
        }

        model.addAttribute("note", note);
        return "note";
    }

    // The GET /logout mapping is removed — Spring Security handles /logout via POST
    // with CSRF protection. A GET /logout would bypass CSRF and allow logout CSRF attacks.
}
