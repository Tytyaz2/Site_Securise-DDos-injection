package com.app.controller;

import com.app.security.service.UserService;
import com.app.security.tableBDD.Note;
import com.app.security.tableBDD.User;
import com.app.security.service.NoteService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.List;

@Controller
public class HomeController {

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

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("==> Utilisateur connecté : " + principal.getName());
        auth.getAuthorities().forEach(a -> System.out.println("Rôle = " + a.getAuthority()));

        String username = principal.getName();
        User user = userService.findByUsername(username);
        if (user == null) {
            return "redirect:/login";
        }

        List<Note> notes = noteService.getNotesByUser(user);
        model.addAttribute("notes", notes);
        return "home";
    }

    @PostMapping("/home/add")
    public String addNote(@RequestParam String title,
                          @RequestParam String content,
                          Principal principal,
                          RedirectAttributes redirectAttributes) {
        if (principal == null) return "redirect:/login";

        String username = principal.getName();
        User user = userService.findByUsername(username);
        if (user == null) return "redirect:/login";

        noteService.createNote(title, content, user);
        redirectAttributes.addFlashAttribute("message", "Note ajoutée avec succès !");
        return "redirect:/home";
    }

    @GetMapping("/home/note/{id}")
    public String editNoteForm(@PathVariable Long id, Model model, Principal principal) {
        if (principal == null) return "redirect:/login";

        Note note = noteService.getNoteById(id);
        if (note == null) return "redirect:/home";

        String username = principal.getName();
        if (!note.getUser().getUsername().equals(username)) return "redirect:/home";

        model.addAttribute("note", note);
        return "note";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:/login";
    }
}
