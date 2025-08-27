package com.bookshop.controller;

import com.bookshop.model.*;
import com.bookshop.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;

@Controller
@RequestMapping("/customer")
public class CustomerController {
    private static final Logger logger = LoggerFactory.getLogger(CustomerController.class);

    @Autowired
    private BookService bookService;

    @Autowired
    private UserService userService;

    @Autowired
    private CartService cartService;

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping("/books")
    public String viewBooks(Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        logger.info("Books page accessed by user: {}", username);

        model.addAttribute("books", bookService.getAllBooks());
        return "customer/books";
    }

    @PostMapping("/cart/add")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN')")
    public String addToCart(@RequestParam @NotNull Long bookId,
                            @RequestParam(defaultValue = "1") @Min(1) int quantity,
                            HttpSession session,
                            RedirectAttributes redirectAttributes) {
        User user = userService.getCurrentUser(session);
        if (user == null) {
            logger.warn("Unauthenticated cart access attempt");
            return "redirect:/login";
        }

        Book book = bookService.getBookById(bookId);
        if (book == null) {
            logger.warn("Attempt to add non-existent book {} to cart by user {}", bookId, user.getUsername());
            redirectAttributes.addFlashAttribute("error", "Book not found");
            return "redirect:/customer/books";
        }

        if (quantity > book.getCopies()) {
            logger.warn("User {} attempted to add {} copies of book {} but only {} available",
                    user.getUsername(), quantity, book.getTitle(), book.getCopies());
            redirectAttributes.addFlashAttribute("error",
                    "Only " + book.getCopies() + " copies available");
            return "redirect:/customer/books";
        }

        cartService.addToCart(user, bookId, quantity);

        logger.info("User {} added {} copies of '{}' to cart",
                user.getUsername(), quantity, book.getTitle());
        auditLogService.logUserAction(user.getUsername(), "CART_ADD",
                "Book: " + book.getTitle() + ", Quantity: " + quantity);

        redirectAttributes.addFlashAttribute("message",
                "'" + book.getTitle() + "' added to cart successfully!");

        return "redirect:/customer/books";
    }
    // test 1


    @GetMapping("/cart")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN')")
    public String viewCart(HttpSession session, Model model) {
        User user = userService.getCurrentUser(session);
        if (user == null) {
            logger.warn("Unauthenticated cart view attempt");
            return "redirect:/login";
        }

        Cart cart = cartService.getCartByUser(user);
        model.addAttribute("cart", cart);

        logger.info("User {} viewed cart", user.getUsername());
        return "customer/cart";
    }

    @PostMapping("/cart/remove/{itemId}")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN')")
    public String removeFromCart(@PathVariable Long itemId,
                                 HttpSession session,
                                 RedirectAttributes redirectAttributes) {
        User user = userService.getCurrentUser(session);
        if (user == null) {
            logger.warn("Unauthenticated cart removal attempt");
            return "redirect:/login";
        }

        Cart cart = cartService.getCartByUser(user);
        String bookTitle = "";

        if (cart != null && cart.getItems() != null) {
            CartItem item = cart.getItems().stream()
                    .filter(i -> i.getId().equals(itemId))
                    .findFirst()
                    .orElse(null);

            if (item != null) {
                // Verify the item belongs to the user's cart
                if (!item.getCart().getUser().getId().equals(user.getId())) {
                    logger.error("User {} attempted to remove item from another user's cart",
                            user.getUsername());
                    auditLogService.logSecurityEvent("UNAUTHORIZED_ACCESS",
                            user.getUsername(),
                            "Attempted cart manipulation");
                    redirectAttributes.addFlashAttribute("error", "Unauthorized action");
                    return "redirect:/customer/cart";
                }

                if (item.getBook() != null) {
                    bookTitle = item.getBook().getTitle();
                }
            }
        }

        cartService.removeFromCart(user, itemId);

        logger.info("User {} removed '{}' from cart", user.getUsername(), bookTitle);
        auditLogService.logUserAction(user.getUsername(), "CART_REMOVE", "Book: " + bookTitle);

        redirectAttributes.addFlashAttribute("message",
                "'" + bookTitle + "' was removed from your cart.");

        return "redirect:/customer/cart";
    }

    @GetMapping("/checkout")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN')")
    public String showCheckout(HttpSession session, Model model) {
        User user = userService.getCurrentUser(session);
        if (user == null) {
            logger.warn("Unauthenticated checkout attempt");
            return "redirect:/login";
        }

        Cart cart = cartService.getCartByUser(user);
        if (cart == null || cart.getItems() == null || cart.getItems().isEmpty()) {
            logger.info("User {} attempted checkout with empty cart", user.getUsername());
            return "redirect:/customer/cart";
        }

        model.addAttribute("cart", cart);
        logger.info("User {} accessed checkout page", user.getUsername());
        return "customer/checkout";
    }

    @PostMapping("/checkout")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN')")
    public String processCheckout(@RequestParam String creditCard,
                                  HttpSession session,
                                  Model model,
                                  RedirectAttributes redirectAttributes) {
        User user = userService.getCurrentUser(session);
        if (user == null) {
            logger.warn("Unauthenticated checkout processing attempt");
            return "redirect:/login";
        }

        // Basic credit card validation (in production, use proper payment gateway)
        if (!creditCard.matches("\\d{16}")) {
            logger.warn("Invalid credit card format from user {}", user.getUsername());
            model.addAttribute("error", "Invalid credit card format");
            Cart cart = cartService.getCartByUser(user);
            model.addAttribute("cart", cart);
            return "customer/checkout";
        }

        // Log payment attempt (mask credit card)
        String maskedCard = "**** **** **** " + creditCard.substring(12);
        logger.info("Payment attempt by user {} with card {}", user.getUsername(), maskedCard);
        auditLogService.logUserAction(user.getUsername(), "CHECKOUT_ATTEMPT",
                "Card: " + maskedCard);

        // Process the checkout and update inventory
        boolean success = cartService.processCheckout(user);

        if (success) {
            logger.info("Successful order placed by user {}", user.getUsername());
            auditLogService.logUserAction(user.getUsername(), "ORDER_PLACED",
                    "Order completed successfully");
            model.addAttribute("success", "Order placed successfully!");
            return "customer/checkout";
        } else {
            logger.warn("Checkout failed for user {} - insufficient inventory", user.getUsername());
            model.addAttribute("error",
                    "Some items are no longer available in the requested quantity.");
            Cart cart = cartService.getCartByUser(user);
            model.addAttribute("cart", cart);
            return "customer/checkout";
        }
    }

}
