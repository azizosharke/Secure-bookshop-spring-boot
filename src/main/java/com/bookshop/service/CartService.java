package com.bookshop.service;

import com.bookshop.model.*;
import com.bookshop.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class CartService {
    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private CartItemRepository cartItemRepository;

    @Autowired
    private BookRepository bookRepository;

    public Cart getCartByUser(User user) {
        return cartRepository.findByUser(user).orElse(null);
    }

    public void addToCart(User user, Long bookId, int quantity) {
        Cart cart = getCartByUser(user);
        Book book = bookRepository.findById(bookId).orElse(null);

        if (cart == null) {
            // Create cart if it doesn't exist
            cart = new Cart(user);
            cart = cartRepository.save(cart);
        }

        if (book != null && book.getCopies() >= quantity) {
            // Check if item already exists in cart
            CartItem existingItem = cart.getItems().stream()
                    .filter(item -> item.getBook().getId().equals(bookId))
                    .findFirst()
                    .orElse(null);

            if (existingItem != null) {
                // Check if total quantity doesn't exceed available copies
                int newQuantity = existingItem.getQuantity() + quantity;
                if (newQuantity <= book.getCopies()) {
                    existingItem.setQuantity(newQuantity);
                }
            } else {
                CartItem newItem = new CartItem(cart, book, quantity);
                cart.getItems().add(newItem);
            }

            cartRepository.save(cart);
        }
    }

    public void removeFromCart(User user, Long itemId) {
        Cart cart = getCartByUser(user);
        if (cart != null) {
            cart.getItems().removeIf(item -> item.getId().equals(itemId));
            cartRepository.save(cart);
        }
    }

    public void clearCart(User user) {
        Cart cart = getCartByUser(user);
        if (cart != null) {
            cart.getItems().clear();
            cartRepository.save(cart);
        }
    }


    @Transactional
    public boolean processCheckout(User user) {
        Cart cart = getCartByUser(user);
        if (cart == null || cart.getItems().isEmpty()) {
            return false;
        }


        for (CartItem item : cart.getItems()) {
            Book book = item.getBook();
            if (book.getCopies() < item.getQuantity()) {
                return false;
            }
        }


        for (CartItem item : cart.getItems()) {
            Book book = item.getBook();
            book.setCopies(book.getCopies() - item.getQuantity());
            bookRepository.save(book);
        }


        clearCart(user);

        return true;
    }
}