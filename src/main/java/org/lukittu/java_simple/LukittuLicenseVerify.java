package org.lukittu.java_simple;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

/**
 * Handles license verification and validation for the Lukittu licensing system.
 * Manages the communication with the license server, validates responses,
 * and performs cryptographic verification of license challenges.
 * 
 * ⚠️ SECURITY WARNING FOR PRODUCTION USE ⚠️
 * 
 * THIS IS A DEMONSTRATION IMPLEMENTATION ONLY.
 * 
 * In a production environment:
 * 1. This entire class should be heavily obfuscated
 * 2. All constants (API URLs, team ID, product ID, public key) should be
 * hardcoded
 * and encrypted/obfuscated rather than loaded from config
 * 3. Only the license key itself should be configurable by end users
 * 4. Add anti-tampering measures to detect modifications to your code
 * 5. Consider using native code protection (JNI/JNIC) for critical sections
 * 
 * Failure to properly protect this code may result in license bypass attempts.
 */
public class LukittuLicenseVerify {

    // Constants for API communication
    private static final String RESULT_KEY = "result";
    private static final String VALID_KEY = "valid";
    private static final String API_BASE_URL = "https://app.lukittu.com/api/v1/client/teams";
    private static final String VERIFY_ENDPOINT = "/verification/verify";
    private static final String HEARTBEAT_ENDPOINT = "/verification/heartbeat";
    private static final String VERSION = "1.0.0";
    private static final int TIMEOUT_MILLIS = 10000; // 10 seconds
    private static final String ERROR_CODE_KEY = "code";
    private static final String ERROR_DETAILS_KEY = "details";

    // Static variables
    /**
     * Unique identifier for this server/device installation
     */
    public static String DEVICE_IDENTIFIER;

    /**
     * Map of error codes to user-friendly error messages
     */
    private static final Map<String, String> ERROR_MESSAGES;

    /**
     * JSON parser/formatter for API communication
     */
    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .setPrettyPrinting()
            .create();

    // Initialize static error messages
    static {
        Map<String, String> messages = new HashMap<>();
        messages.put("RELEASE_NOT_FOUND", "Invalid version specified in config.");
        messages.put("LICENSE_NOT_FOUND", "License not specified in config.yml, or it is invalid.");
        messages.put("IP_LIMIT_REACHED",
                "License's IP address limit has been reached. Contact support if you have issues with this.");
        messages.put("MAXIMUM_CONCURRENT_SEATS", "Maximum devices connected from the same license.");
        messages.put("RATE_LIMIT",
                "Too many connections in a short time from the same IP address. Please wait a while!");
        messages.put("LICENSE_EXPIRED", "The license has expired.");
        messages.put("INTERNAL_SERVER_ERROR", "Upstream service has issues. Please notify support!");
        messages.put("BAD_REQUEST", "Invalid request format or parameters. Check your license configuration.");
        ERROR_MESSAGES = Collections.unmodifiableMap(messages);
    }

    /**
     * Main license verification method that initiates the verification process.
     * Generates a challenge, sends it to the license server, and validates the
     * response.
     *
     * ⚠️ SECURITY NOTE: In production, only licenseKey should come from
     * configuration.
     * The teamId, productId, and publicKey should be hardcoded, obfuscated
     * constants.
     *
     * @param licenseKey The license key from config
     * @param teamId     The team ID from config (should be hardcoded in production)
     * @param productId  The product ID from config (should be hardcoded in
     *                   production)
     * @param publicKey  The public key used to verify the server's signature
     *                   (should be hardcoded in production)
     * @throws IOException If a network or server error occurs
     * @throws Exception   If validation fails for any reason
     */
    public static void verifyKey(String licenseKey, String teamId, String productId, String publicKey)
            throws Exception {
        DEVICE_IDENTIFIER = getHardwareIdentifier();

        // Generate a random challenge
        var challenge = generateRandomChallenge();

        // Construct the URL for the API call with team ID
        var url = API_BASE_URL + "/" + teamId + VERIFY_ENDPOINT;

        var jsonBody = String.format("""
                {
                  "licenseKey": "%s",
                  "productId": "%s",
                  "challenge": "%s",
                  "version": "%s",
                  "deviceIdentifier": "%s"
                }""", licenseKey, productId, challenge, VERSION, DEVICE_IDENTIFIER);

        boolean verificationSuccess = fetchAndHandleResponse(url, jsonBody, publicKey, challenge);

        // Throw exception if verification failed to ensure it's caught in Simple's
        // onEnable
        if (!verificationSuccess) {
            throw new Exception("License verification failed");
        }
    }

    /**
     * Generates a random challenge string to prevent replay attacks.
     * The server will sign this challenge in its response.
     * 
     * @return A secure random hex string to use as challenge
     */
    private static String generateRandomChallenge() {
        var secureRandom = new SecureRandom();
        var randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return bytesToHex(randomBytes);
    }

    /**
     * Utility method to convert byte arrays to hexadecimal strings.
     *
     * @param bytes The byte array to convert
     * @return A hex string representation of the bytes
     */
    public static String bytesToHex(byte[] bytes) {
        var result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Makes the HTTP request to the license server and processes the response.
     *
     * @param urlString       The full URL of the license API endpoint
     * @param jsonBody        The request body to send
     * @param publicKeyBase64 The public key to verify the response
     * @param challenge       The challenge string that should be signed in the
     *                        response
     * @return true if verification succeeded, false if it failed
     * @throws IOException If a network error occurs
     */
    public static boolean fetchAndHandleResponse(String urlString, String jsonBody, String publicKeyBase64,
            String challenge) throws IOException {
        HttpURLConnection connection = null;
        boolean success = false;

        try {
            var url = URI.create(urlString).toURL();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("User-Agent", buildUserAgent());
            connection.setConnectTimeout(TIMEOUT_MILLIS);
            connection.setReadTimeout(TIMEOUT_MILLIS);
            connection.setDoOutput(true);

            try (var os = connection.getOutputStream()) {
                var input = jsonBody.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (var inputStream = connection.getInputStream()) {
                    success = handleJsonResponse(inputStream, publicKeyBase64, challenge);
                }
            } else {
                try (var errorStream = connection.getErrorStream()) {
                    // Try to extract error details from the error response
                    if (errorStream != null) {
                        handleJsonResponse(errorStream, null, null);
                    }
                }
                // Show HTTP error if in 4xx or 5xx range
                if (responseCode >= 400) {
                    Simple.INSTANCE.logMessage("HTTP Error: " + responseCode +
                            " - Check your team ID, product ID and license key");
                }
            }
        } catch (Exception e) {
            Simple.INSTANCE.getLogger().log(Level.SEVERE, "Connection to Lukittu service failed", e);
            Simple.INSTANCE.logMessage("Connection failure! Check server connectivity");
            try {
                if (connection != null && connection.getErrorStream() != null) {
                    handleJsonResponse(connection.getErrorStream(), null, null);
                }
            } catch (IOException e1) {
                Simple.INSTANCE.getLogger().log(Level.SEVERE, "Failed to parse error response", e1);
            }
            throw new IOException("Connection to license server failed", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return success;
    }

    /**
     * Parses and validates the JSON response from the license server.
     * If verification succeeds, it sets the valid state in the main plugin.
     *
     * @param inputStream The input stream containing the JSON response
     * @param publicKey   The public key for signature verification
     * @param challenge   The original challenge to verify
     * @throws IOException If there's an error reading the response
     * @return true if validation was successful, false if errors were encountered
     */
    private static boolean handleJsonResponse(InputStream inputStream, String publicKey, String challenge)
            throws IOException {
        if (inputStream == null) {
            throw new IOException("Input stream is null");
        }

        try (var reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            var json = GSON.fromJson(reader, JsonObject.class);

            // Log the full JSON response for debugging
            var respString = GSON.toJson(json);
            logResponse(respString);

            // Check if this is a success response that needs validation
            if (publicKey != null && challenge != null) {
                if (validateResponse(json) && validateChallenge(json, challenge, publicKey)) {
                    setValidState();
                    return true;
                }
            }

            // At this point, there's an error we need to handle
            if (json.has(RESULT_KEY)) {
                var result = json.getAsJsonObject(RESULT_KEY);

                // Extract error details if available
                if (result.has(ERROR_CODE_KEY)) {
                    String errorCode = result.get(ERROR_CODE_KEY).getAsString();
                    String errorMessage = ERROR_MESSAGES.getOrDefault(errorCode,
                            "Lukittu license check failed with code: " + errorCode);

                    // Add details if available
                    if (result.has(ERROR_DETAILS_KEY)) {
                        errorMessage += " (" + result.get(ERROR_DETAILS_KEY).getAsString() + ")";
                    }

                    Simple.INSTANCE.logMessage("Error: " + errorMessage);
                    return false;
                }
            }

            // If we didn't find specific error info, use the general handling
            return !handleErrorCodes(respString);
        }
    }

    /**
     * Validates the digital signature of the challenge in the server response.
     * This proves the response came from the legitimate license server.
     *
     * @param response          The JSON response from the server
     * @param originalChallenge The original challenge we sent
     * @param base64PublicKey   The public key to verify the signature
     * @return true if the signature is valid, false otherwise
     */
    public static boolean validateChallenge(JsonObject response, String originalChallenge, String base64PublicKey) {
        try {
            if (!validateResponse(response) || originalChallenge == null || base64PublicKey == null) {
                return false;
            }

            var signedChallenge = response.getAsJsonObject(RESULT_KEY)
                    .get("challengeResponse").getAsString();

            return verifySignature(originalChallenge, signedChallenge, base64PublicKey);
        } catch (Exception e) {
            Simple.INSTANCE.getLogger().log(Level.SEVERE, "Challenge validation failed", e);
            Simple.INSTANCE.logMessage("Signature verification failed! Possible tampering detected");
            return false;
        }
    }

    /**
     * Performs the actual cryptographic signature verification.
     * Uses RSA with SHA256 to verify that the challenge was signed by the license
     * server.
     *
     * @param challenge       The original challenge string
     * @param signatureHex    The hex-encoded signature to verify
     * @param base64PublicKey The base64-encoded public key
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verifySignature(String challenge, String signatureHex, String base64PublicKey) {
        try {
            var signatureBytes = hexStringToByteArray(signatureHex);
            var decodedKeyBytes = Base64.getDecoder().decode(base64PublicKey);

            var decodedKeyString = new String(decodedKeyBytes)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            var publicKeyBytes = Base64.getDecoder().decode(decodedKeyString);
            var keySpec = new X509EncodedKeySpec(publicKeyBytes);
            var keyFactory = KeyFactory.getInstance("RSA");
            var publicKey = keyFactory.generatePublic(keySpec);

            var signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(challenge.getBytes());

            return signature.verify(signatureBytes);
        } catch (IllegalArgumentException e) {
            Simple.INSTANCE.getLogger().log(Level.SEVERE, "Invalid Base64 input for public key", e);
            Simple.INSTANCE.logMessage("Invalid public key format! Contact support");
            return false;
        } catch (Exception e) {
            Simple.INSTANCE.getLogger().log(Level.SEVERE, "Signature verification failed", e);
            return false;
        }
    }

    /**
     * Utility method to convert a hex string to a byte array.
     *
     * @param hex The hex string to convert
     * @return The resulting byte array
     */
    private static byte[] hexStringToByteArray(String hex) {
        var len = hex.length();
        var data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Checks if the license server response indicates a valid license.
     *
     * @param json The JSON response object to validate
     * @return true if the license is valid, false otherwise
     */
    private static boolean validateResponse(JsonObject json) {
        try {
            var result = json.getAsJsonObject(RESULT_KEY);
            return result != null &&
                    result.has(VALID_KEY) &&
                    result.get(VALID_KEY).getAsBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Updates the main plugin to indicate the license is valid.
     * Uses reflection to avoid direct dependencies.
     */
    private static void setValidState() {
        try {
            var validField = Simple.class.getDeclaredField("valid");
            validField.setAccessible(true);
            validField.set(Simple.INSTANCE, true);
        } catch (Exception e) {
            Simple.INSTANCE.getLogger().log(Level.WARNING, "Failed to set valid state", e);
        }
    }

    /**
     * Builds a consistent User-Agent string for API requests.
     * Helps with tracking and debugging on the server side.
     *
     * @return The formatted User-Agent string
     */
    private static String buildUserAgent() {
        return String.format("LukittuLoader/%s (%s %s; %s)",
                VERSION,
                System.getProperty("os.name"),
                System.getProperty("os.version"),
                System.getProperty("os.arch"));
    }

    /**
     * Logs API responses for debugging purposes.
     * Useful for diagnosing license problems.
     *
     * @param response The JSON response string
     */
    private static void logResponse(String response) {
        if (response != null) {
            Simple.INSTANCE.getLogger().info("Received JSON response (pretty printed):");
            Simple.INSTANCE.getLogger().info(response);
        }
    }

    /**
     * Checks API responses for known error codes and provides user-friendly
     * messages.
     *
     * @param response The response string to check
     * @return true if an error was found and handled, false otherwise
     */
    private static boolean handleErrorCodes(final String response) {
        if (response == null) {
            return false;
        }

        // Find specific error in the response
        var errorEntry = findErrorInResponse(response);

        // Handle error if found
        if (errorEntry.isPresent()) {
            var errorMessage = errorEntry.get().getValue();
            Simple.INSTANCE.getLogger().severe(errorMessage);
            Simple.INSTANCE.logMessage("Error: " + errorMessage);
            return true;
        }

        // Generic error for any validation failure not otherwise caught
        if (response.contains("\"valid\":false")) {
            Simple.INSTANCE.logMessage("License validation failed. Check your license configuration");
            return true;
        }

        // No error found
        return false;
    }

    /**
     * Finds the first matching error code in the response.
     * 
     * @param response The API response to search
     * @return An Optional containing the matching error entry, or empty if none
     *         found
     */
    private static Optional<Map.Entry<String, String>> findErrorInResponse(String response) {
        return ERROR_MESSAGES.entrySet().stream()
                .filter(entry -> response.contains(entry.getKey()))
                .findFirst();
    }

    /**
     * Sends a periodic heartbeat to the license server.
     * This keeps the license active and helps detect license violations.
     *
     * @param teamId     The team ID associated with the license
     * @param licenseKey The license key to validate
     * @param productId  The product ID associated with the license
     * @throws Exception If there's an error sending the heartbeat
     */
    public static void sendHeartbeat(String teamId, String licenseKey, String productId) throws Exception {
        var urlString = API_BASE_URL + "/" + teamId + HEARTBEAT_ENDPOINT;
        var url = URI.create(urlString).toURL();

        var connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("User-Agent", buildUserAgent());
        connection.setConnectTimeout(TIMEOUT_MILLIS);
        connection.setReadTimeout(TIMEOUT_MILLIS);
        connection.setDoOutput(true);

        var jsonBody = String.format("""
                {
                    "licenseKey": "%s",
                    "productId": "%s",
                    "deviceIdentifier": "%s"
                }""", licenseKey, productId, DEVICE_IDENTIFIER);

        try (var os = connection.getOutputStream()) {
            var input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int responseCode = connection.getResponseCode();

        // Read the response for logging purposes, even if we don't use it
        try (var is = (responseCode < HttpURLConnection.HTTP_BAD_REQUEST)
                ? connection.getInputStream()
                : connection.getErrorStream();
                var br = new BufferedReader(new InputStreamReader(is))) {

            var response = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }

            if (responseCode >= HttpURLConnection.HTTP_BAD_REQUEST) {
                Simple.INSTANCE.getLogger().warning("Heartbeat failed with response code: " + responseCode);
                handleErrorCodes(response.toString());
            }
        } catch (IOException e) {
            Simple.INSTANCE.getLogger().log(Level.WARNING, "Failed to read heartbeat response", e);
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Generates a unique identifier for this server/device based on system
     * properties.
     * Used to limit the number of installations per license.
     * 
     * Note: On virtual machines or containers, this may change between restarts.
     *
     * @return A UUID based on system properties or a random UUID if hardware info
     *         can't be retrieved
     */
    public static String getHardwareIdentifier() {
        try {
            // Use standard approach instead of StructuredTaskScope (preview API)
            var osName = System.getProperty("os.name");
            var osVersion = System.getProperty("os.version");
            var osArch = System.getProperty("os.arch");
            var hostname = InetAddress.getLocalHost().getHostName();

            var combinedIdentifier = osName + osVersion + osArch + hostname;
            return UUID.nameUUIDFromBytes(combinedIdentifier.getBytes()).toString();
        } catch (Exception e) {
            Simple.INSTANCE.getLogger().warning("Failed to get hardware identifier: " + e.getMessage());
            Simple.INSTANCE.logMessage("Hostname retrieval failed, using random identifier");
            return UUID.randomUUID().toString();
        }
    }
}
