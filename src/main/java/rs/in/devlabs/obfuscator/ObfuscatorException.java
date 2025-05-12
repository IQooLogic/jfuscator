package rs.in.devlabs.obfuscator;

/**
 * Exception thrown by the Obfuscator.
 */
public class ObfuscatorException extends Exception {

    /**
     * Creates a new ObfuscatorException with the given message.
     *
     * @param message The exception message
     */
    public ObfuscatorException(String message) {
        super(message);
    }

    /**
     * Creates a new ObfuscatorException with the given message and cause.
     *
     * @param message The exception message
     * @param cause The cause of this exception
     */
    public ObfuscatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
