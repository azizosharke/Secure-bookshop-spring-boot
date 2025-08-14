package com.bookshop.controller;

import com.bookshop.model.Book;
import com.bookshop.service.BookService;
import com.bookshop.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.access.prepost.PreAuthorize;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private BookService bookService;

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        logger.info("Admin dashboard accessed by user: {}", username);

        model.addAttribute("books", bookService.getAllBooks());
        return "admin/dashboard";
    }

    @GetMapping("/book/add")
    public String showAddBookForm(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        logger.info("Add book form accessed by admin: {}", username);

        model.addAttribute("book", new Book());
        return "admin/book-form";
    }

    @GetMapping("/book/edit/{id}")
    public String showEditBookForm(@PathVariable Long id, HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        logger.info("Edit book form accessed for book ID {} by admin: {}", id, username);

        Book book = bookService.getBookById(id);
        if (book == null) {
            logger.warn("Attempted to edit non-existent book with ID: {}", id);
            return "redirect:/admin/dashboard";
        }

        model.addAttribute("book", book);
        return "admin/book-form";
    }

    @PostMapping("/book/save")
    public String saveBook(@Valid @ModelAttribute Book book,
                           HttpSession session,
                           RedirectAttributes redirectAttributes) {
        String username = (String) session.getAttribute("username");
        boolean isNew = book.getId() == null;

        // Validate book data
        if (book.getPrice() != null && book.getPrice().doubleValue() < 0) {
            logger.warn("Invalid price attempted for book by admin: {}", username);
            redirectAttributes.addFlashAttribute("error", "Price cannot be negative");
            return "redirect:/admin/dashboard";
        }

        Book savedBook = bookService.saveBook(book);

        String action = isNew ? "added" : "updated";
        logger.info("Book '{}' {} by admin: {}", savedBook.getTitle(), action, username);
        auditLogService.logAdminAction(username, "BOOK_" + action.toUpperCase(),
                "Book ID: " + savedBook.getId());

        redirectAttributes.addFlashAttribute("successMessage",
                "Book '" + savedBook.getTitle() + "' was successfully " + action + "!");

        return "redirect:/admin/dashboard";
    }

    @PostMapping("/book/delete/{id}")
    public String deleteBook(@PathVariable Long id,
                             HttpSession session,
                             RedirectAttributes redirectAttributes) {
        String username = (String) session.getAttribute("username");

        Book book = bookService.getBookById(id);
        if (book == null) {
            logger.warn("Attempted to delete non-existent book with ID: {} by admin: {}", id, username);
            redirectAttributes.addFlashAttribute("error", "Book not found");
            return "redirect:/admin/dashboard";
        }

        String bookTitle = book.getTitle();
        bookService.deleteBook(id);

        logger.info("Book '{}' deleted by admin: {}", bookTitle, username);
        auditLogService.logAdminAction(username, "BOOK_DELETED", "Book ID: " + id);

        redirectAttributes.addFlashAttribute("successMessage",
                "Book '" + bookTitle + "' was successfully deleted!");

        return "redirect:/admin/dashboard";
    }
}