# IQooLogic Obfuscator for Java

## Introduction
The obfuscator library enables Java programs to encode and decode sensitive values such as passwords to store them in configuration files.

## Installation

### Maven
```xml
<dependency>
    <groupId>rs.in.devlabs</groupId>
    <artifactId>jfuscator</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle
```groovy
implementation 'rs.in.devlabs:jfuscator:1.0.0'
```

## Usage Examples

### Basic Usage
```java
import rs.in.devlabs.obfuscator.Obfuscator;
import rs.in.devlabs.obfuscator.ObfuscatorException;
import java.nio.charset.StandardCharsets;

public class Example {
    public static void main(String[] args) {
        try {
            String originalText = "simple text or password";
            byte[] passphrase = "randompassphrase".getBytes(StandardCharsets.UTF_8);
            
            // Create obfuscator with default settings
            Obfuscator obfuscator = new Obfuscator(passphrase);
            
            // Obfuscate
            String obfuscatedText = obfuscator.obfuscate(originalText);
            System.out.println("Obfuscated text: " + obfuscatedText);
            
            // Unobfuscate
            String unobfuscatedText = obfuscator.unobfuscate(obfuscatedText);
            System.out.println("Unobfuscated text: " + unobfuscatedText);
        } catch (ObfuscatorException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

### Custom Configuration
```java
import rs.in.devlabs.obfuscator.Obfuscator;
import rs.in.devlabs.obfuscator.ObfuscatorConfig;
import rs.in.devlabs.obfuscator.ObfuscatorException;
import java.nio.charset.StandardCharsets;

public class CustomConfigExample {
    public static void main(String[] args) {
        try {
            String originalText = "simple text or password";
            byte[] passphrase = "randompassphrase".getBytes(StandardCharsets.UTF_8);
            
            // Create custom configuration
            ObfuscatorConfig config = ObfuscatorConfig.builder(passphrase)
                .withSaltLength(16)  // Custom salt length (default is 8)
                .withSeparator("#")  // Custom separator (default is "$")
                .build();
            
            // Create obfuscator with custom configuration
            Obfuscator obfuscator = new Obfuscator(passphrase, config);
            
            // Obfuscate
            String obfuscatedText = obfuscator.obfuscate(originalText);
            System.out.println("Obfuscated text: " + obfuscatedText);
            
            // Unobfuscate
            String unobfuscatedText = obfuscator.unobfuscate(obfuscatedText);
            System.out.println("Unobfuscated text: " + unobfuscatedText);
        } catch (ObfuscatorException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

## Features
- AES-GCM encryption for secure obfuscation
- Customizable salt length and separator
- Base64 encoding for safe storage in configuration files
- Compatible with the original Go package format

## Requirements
- Java 8 or higher

## License
The obfuscator package is licensed under the MIT license.
Please see the LICENSE file for details.
