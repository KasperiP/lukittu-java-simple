package org.lukittu.java_simple;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.bukkit.plugin.java.JavaPlugin;

/**
 * Main plugin class for the LukittuSimple plugin with Lukittu license
 * verification.
 * Handles plugin lifecycle, license checks, and periodic heartbeat requests.
 * 
 * ⚠️ SECURITY WARNING FOR PRODUCTION USE ⚠️
 * 
 * This implementation loads all license parameters from configuration for
 * simplicity.
 * In a production environment, only the customer license key should be
 * configurable.
 * 
 * All other Lukittu parameters (team ID, product ID, public key) should be
 * hardcoded
 * in your compiled JAR and protected with code obfuscation to prevent
 * tampering.
 */
public final class Simple extends JavaPlugin {

    /**
     * Static instance of the plugin for global access from other classes.
     */
    public static Simple INSTANCE;

    /**
     * Flag indicating whether the license validation was successful.
     * This is set by the LukittuLicenseVerify class after verification.
     */
    public boolean valid;

    /**
     * Scheduled executor for periodic tasks.
     */
    private ScheduledExecutorService scheduler;

    /**
     * Called when the plugin is enabled by the server.
     * Handles configuration loading, license verification and setup.
     */
    @Override
    public void onEnable() {
        INSTANCE = this;

        // Set up logging format
        setupLogging();

        // Save default config if it doesn't exist
        saveDefaultConfig();

        // Define a record to hold license configuration with proper types
        record LicenseConfig(String key, String teamId, String productId, String publicKey) {
        }

        // NOTE: In production, only load the license key from config
        // and hardcode other values for security
        var licenseConfig = new LicenseConfig(
                getConfig().getString("license.key", ""),
                getConfig().getString("license.team-id", ""), // Should be hardcoded in production
                getConfig().getString("license.product-id", ""), // Should be hardcoded in production
                getConfig().getString("license.public-key", "")); // Should be hardcoded in production

        // Check if all required license configuration values are provided
        if (licenseConfig.key().isEmpty() || licenseConfig.teamId().isEmpty() || licenseConfig.productId().isEmpty()) {
            logMessage("License configuration missing. Check your config.yml!");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // Verify the license key on startup
        getLogger().info("Verifying Lukittu license...");
        try {
            LukittuLicenseVerify.verifyKey(
                    licenseConfig.key(),
                    licenseConfig.teamId(),
                    licenseConfig.productId(),
                    licenseConfig.publicKey());

            if (!valid) {
                // Verification already showed the appropriate error message
                getServer().getPluginManager().disablePlugin(this);
                return;
            }

            // Set up periodic heartbeat checks every 15 minutes
            setupHeartbeatScheduler(
                    licenseConfig.key(),
                    licenseConfig.teamId(),
                    licenseConfig.productId());

            logMessage("Plugin enabled with valid license");
        } catch (Exception e) {
            getLogger().severe("Unexpected error during license verification: " + e.getMessage());
            logMessage("License verification failed due to an unexpected error");
            getServer().getPluginManager().disablePlugin(this);
        }
    }

    /**
     * Sets up a scheduled task to send periodic heartbeat requests to the license
     * server.
     * This keeps the license active and validates it's still in use.
     *
     * @param licenseKey The license key to validate
     * @param teamId     The team ID for the license API
     * @param productId  The product ID for the license API
     */
    private void setupHeartbeatScheduler(String licenseKey, String teamId, String productId) {
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            try {
                LukittuLicenseVerify.sendHeartbeat(teamId, licenseKey, productId);
                getLogger().fine("Heartbeat sent successfully");
            } catch (Exception e) {
                getLogger().log(Level.WARNING, "Failed to send heartbeat", e);
            }
        }, 15, 15, TimeUnit.MINUTES);
    }

    /**
     * Configure default logging level for the plugin
     */
    private void setupLogging() {
        getLogger().setLevel(Level.INFO);
    }

    /**
     * Logs a license-related message with a specific prefix to make it easily
     * identifiable
     * 
     * @param message The message to log
     */
    public void logMessage(String message) {
        getLogger().info("LUKITTU LICENSE: " + message);
    }

    /**
     * Called when the plugin is disabled by the server.
     * Handles graceful shutdown of background tasks.
     */
    @Override
    public void onDisable() {
        // Shutdown the scheduler if it exists
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        getLogger().info("LukittuSimple plugin disabled!");
    }
}
