package com.lopessystem.authserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.util.Objects.nonNull;
import static org.springframework.util.StringUtils.hasText;

/**
 * The type Md 5 password encoder.
 */
@Slf4j
public class MD5PasswordEncoder implements PasswordEncoder {

    @SuppressWarnings({"java:S4790"})
    private static MessageDigest md = null;

    static {
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            log.error("Encoding error. Invalid algorithm.", ex);
        }
    }

    @Override
    public String encode(CharSequence charSequence) {
        return encrypt(charSequence.toString());
    }

    @Override
    public boolean matches(CharSequence typed, String userPassword) {
        String password;
        String encryptedPassword;

        String part1 = splitValue(userPassword, 0);
        if (!part1.equalsIgnoreCase(userPassword)) {
            password = concatPassword(part1, typed.toString());
            encryptedPassword = encrypt(password);
        } else {
            encryptedPassword = encrypt(typed.toString());
        }

        return hasText(encryptedPassword) && comparePassword(encryptedPassword, userPassword);
    }

    /**
     * Encode md 5 string.
     *
     * @param userPk   the user pk
     * @param password the password
     * @return the string
     */
    public String encodeMD5(final Integer userPk, final String password) {
        final String saltedPassword = String.format("%s%s", userPk, password);
        final String encodedPassword = encrypt(saltedPassword);

        return nonNull(encodedPassword) ? encodedPassword.toLowerCase() : null;
    }

    private static char[] hexCodes(byte[] text) {
        char[] hexOutput = new char[text.length * 2];
        String hexString;

        for (int i = 0; i < text.length; i++) {
            hexString = "00" + Integer.toHexString(text[i]);
            hexString.toUpperCase().getChars(hexString.length() - 2,
                    hexString.length(), hexOutput, i * 2);
        }
        return hexOutput;
    }

    /**
     * Encrypt string.
     *
     * @param text the text
     * @return the string
     */
    public static String encrypt(String text) {
        return nonNull(md) ? new String(hexCodes(md.digest(text.getBytes()))) : null;
    }

    /**
     * Compare password boolean.
     *
     * @param typed    the typed
     * @param expected the expected
     * @return the boolean
     */
    public boolean comparePassword(String typed, String expected) {
        return typed.equalsIgnoreCase(splitValue(expected, 1));
    }

    /**
     * Split value string.
     *
     * @param text     the text
     * @param position the position
     * @return the string
     */
    public String splitValue(String text, int position) {
        String[] pk = text.split(":");
        if (pk.length == 2) {
            return pk[position];
        } else {
            return text;
        }
    }

    /**
     * Concat password string.
     *
     * @param pk       the pk
     * @param password the password
     * @return the string
     */
    public String concatPassword(String pk, String password) {
        return pk + password;
    }

}
