package com.bookshop.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.RequestDispatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class CustomErrorController implements ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(CustomErrorController.class);

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String errorMessage = "An unexpected error occurred";

        if (status != null) {
            Integer statusCode = Integer.valueOf(status.toString());

            // Log the error but don't expose details to user
            logger.error("Error occurred with status code: {}, URI: {}",
                    statusCode,
                    request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI));

            if (statusCode == 404) {
                errorMessage = "The page you are looking for could not be found";
            } else if (statusCode == 403) {
                errorMessage = "You do not have permission to access this resource";
            } else if (statusCode == 500) {
                errorMessage = "An internal server error occurred. Please try again later";
            }

            model.addAttribute("statusCode", statusCode);
        }

        model.addAttribute("errorMessage", errorMessage);
        return "error";
    }
}