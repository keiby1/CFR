package org.example;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

public class Main {
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                String response = handleGet(exchange);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } else if ("POST".equals(exchange.getRequestMethod())) {
                String response = handlePost(exchange);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        });
        server.start();
    }

    private static String handleGet(HttpExchange exchange) throws IOException {
        String csrfToken = generateCSRFToken();
        // Set cookie with token
        exchange.getResponseHeaders().add("Set-Cookie", "csrf=" + csrfToken + "; HttpOnly; Path=/");

        // Logging for debugging
        System.out.println("Generated CSRF Token: " + csrfToken);

        return "<html><body>" +
                "<h1>Welcome!</h1>" +
                "<form action='/' method='POST'>" +
                "<input type='hidden' name='csrf_token' value='" + csrfToken + "' />" +
                "<input type='text' name='data' placeholder='Enter some data' required />" +
                "<button type='submit'>Submit</button>" +
                "</form></body></html>";
    }

    private static String handlePost(HttpExchange exchange) throws IOException {
        String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String submittedToken = extractParameter(requestBody, "csrf_token");
        String data = extractParameter(requestBody, "data"); //token from input

        // Extract CSRF token from cookie
        String csrfCookie = getCookieValue(exchange.getRequestHeaders().getFirst("Cookie"), "csrf");

        // Logging values for debugging
        System.out.println("Submitted Token: " + submittedToken);
        System.out.println("CSRF Cookie: " + csrfCookie);

        // Decode the submitted token
        String decodedSubmittedToken = java.net.URLDecoder.decode(submittedToken, StandardCharsets.UTF_8.toString());

        // Check for token existence before comparison
        if (csrfCookie == null && decodedSubmittedToken == null && !csrfCookie.equals(decodedSubmittedToken)) {
            System.out.println("Invalid CSRF token");
            return "Invalid CSRF token";
        }

        return "Token OK! Data submitted: " + data;
    }

    private static String generateCSRFToken() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes); // Generate token
    }

    private static String extractParameter(String request, String parameter) {
        String[] pairs = request.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length > 1 && keyValue[0].equals(parameter)) {
                return keyValue[1]; // Return parameter value
            }
        }
        return null;
    }

    private static String getCookieValue(String cookieHeader, String cookieName) {
        if (cookieHeader != null && !cookieHeader.isEmpty()) {
            String[] cookies = cookieHeader.split("; ");
            for (String cookie : cookies) {
                String[] nameValue = cookie.split("=");
                if (nameValue.length > 1 && nameValue[0].equals(cookieName)) {
                    return nameValue[1]; // Return cookie value
                }
            }
        }
        return null;
    }
}