# LukittuSimple - License Protected Minecraft Plugin

A simple Bukkit/Spigot plugin demonstrating integration with the Lukittu license verification system.

## Overview

This project showcases how to implement a robust license verification system for your Minecraft plugins. It includes:

-   License key validation on plugin startup
-   Regular license heartbeat checks
-   Cryptographic challenge-response verification
-   Proper error handling for various license scenarios

## Setup and Installation

1. Clone this repository
2. Update the licensing details in `src/main/resources/config.yml`:
    - `license.key`: Your license key
    - `license.team-id`: Your Lukittu team ID
    - `license.product-id`: Your Lukittu product ID
    - `license.public-key`: Your RSA public key for verification
3. Build with Maven: `mvn clean package`
4. Copy the generated JAR from `target/` to your server's `plugins/` folder

## Building

```bash
# With Maven installed
mvn clean package

# Or using the Maven wrapper (if available)
./mvnw clean package
```

## ⚠️ IMPORTANT SECURITY WARNING FOR PRODUCTION USE ⚠️

This repository is provided as a **demonstration implementation only** and is not intended for direct use in production plugins without additional security hardening.

### Security Considerations

When implementing license protection in a real-world plugin:

1. **Never expose sensitive details in configuration files**

    - Only the license key should be configurable by end users
    - All other values (team ID, product ID, public key) should be hardcoded and obfuscated

2. **Apply code obfuscation**

    - Use tools like ProGuard, Allatori, or Zelix KlassMaster
    - Rename classes, methods, and fields to hinder reverse engineering
    - Apply string encryption, especially for constants like API URLs

3. **Implement anti-tampering measures**

    - Add integrity checks throughout your code
    - Use multiple verification points to ensure consistent license validation
    - Consider native code protection (JNI/JNIC) for critical sections

4. **Protect application logic**
    - Implement license checks in multiple places, not just at startup
    - Add time-based validation that varies with each installation
    - Mix verification logic with core functionality to make bypass more difficult

## License

This example code is provided for educational purposes. For use in your own plugins, ensure you have appropriate licensing for all dependencies and adhere to Lukittu's terms of service.
