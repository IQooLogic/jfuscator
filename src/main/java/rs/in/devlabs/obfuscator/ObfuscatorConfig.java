package rs.in.devlabs.obfuscator;

/**
 * Configuration class for the Obfuscator.
 */
public class ObfuscatorConfig {
    private final byte[] passphrase;
    private Integer saltLength;
    private String separator;

    /**
     * Creates a new configuration with default values.
     *
     * @param passphrase The passphrase used for obfuscation
     */
    public ObfuscatorConfig(byte[] passphrase) {
        this.passphrase = passphrase;
        this.saltLength = Obfuscator.DEFAULT_SALT_LENGTH;
        this.separator = Obfuscator.DEFAULT_SEPARATOR;
    }

    /**
     * Creates a builder for this configuration.
     *
     * @param passphrase The passphrase used for obfuscation
     * @return The builder
     */
    public static Builder builder(byte[] passphrase) {
        return new Builder(passphrase);
    }

    /**
     * Gets the passphrase.
     *
     * @return The passphrase
     */
    public byte[] getPassphrase() {
        return passphrase;
    }

    /**
     * Gets the salt length.
     *
     * @return The salt length
     */
    public Integer getSaltLength() {
        return saltLength;
    }

    /**
     * Sets the salt length.
     *
     * @param saltLength The salt length
     * @throws IllegalArgumentException if salt length is less than or equal to 0
     */
    public void setSaltLength(Integer saltLength) {
        if (saltLength != null && saltLength <= 0) {
            throw new IllegalArgumentException("Salt length must be greater than 0");
        }
        this.saltLength = saltLength;
    }

    /**
     * Gets the separator.
     *
     * @return The separator
     */
    public String getSeparator() {
        return separator;
    }

    /**
     * Sets the separator.
     *
     * @param separator The separator
     */
    public void setSeparator(String separator) {
        this.separator = separator;
    }

    /**
     * Builder class for ObfuscatorConfig.
     */
    public static class Builder {
        private final ObfuscatorConfig config;

        private Builder(byte[] passphrase) {
            this.config = new ObfuscatorConfig(passphrase);
        }

        /**
         * Sets the salt length.
         *
         * @param saltLength The salt length
         * @return The builder
         */
        public Builder withSaltLength(int saltLength) {
            config.setSaltLength(saltLength);
            return this;
        }

        /**
         * Sets the separator.
         *
         * @param separator The separator
         * @return The builder
         */
        public Builder withSeparator(String separator) {
            config.setSeparator(separator);
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return The built configuration
         */
        public ObfuscatorConfig build() {
            return config;
        }
    }
}
