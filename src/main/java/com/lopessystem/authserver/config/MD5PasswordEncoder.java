package com.lopessystem.authserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

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
        return criptografarMd5(charSequence.toString());
    }

    @Override
    public boolean matches(CharSequence digitado, String senhaBanco) {
        String password;
        String encryptedPassword;

        String part1 = separarValor(senhaBanco, 0);
        if (!part1.equalsIgnoreCase(senhaBanco)) {
            password = concatSenha(part1, digitado.toString());
            encryptedPassword = criptografarMd5(password);
        } else {
            encryptedPassword = criptografarMd5(digitado.toString());
        }

        return hasText(encryptedPassword) && compararSenhas(encryptedPassword, senhaBanco);
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
        final String encodedPassword = criptografarMd5(saltedPassword);

        return Objects.nonNull(encodedPassword) ? encodedPassword.toLowerCase() : null;
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
     * Criptografar md 5 string.
     *
     * @param pwd the pwd
     * @return the string
     */
    public static String criptografarMd5(String pwd) {
        if (md != null) {
            return new String(hexCodes(md.digest(pwd.getBytes())));
        }
        return null;
    }

    /**
     * Comparar senhas boolean.
     *
     * @param digitado the digitado
     * @param esperado the esperado
     * @return the boolean
     */
    public boolean compararSenhas(String digitado, String esperado) {
        return digitado.equalsIgnoreCase(separarValor(esperado, 1));
    }

    /**
     * Separar valor string.
     *
     * @param texto   the texto
     * @param posicao the posicao
     * @return the string
     */
    public String separarValor(String texto, int posicao) {
        String[] pk = texto.split(":");
        if (pk.length == 2) {
            return pk[posicao];
        } else {
            return texto;
        }
    }

    /**
     * Concat senha string.
     *
     * @param pk    the pk
     * @param senha the senha
     * @return the string
     */
    public String concatSenha(String pk, String senha) {
        return pk + senha;
    }

}
