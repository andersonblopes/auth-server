package com.lopessystem.authserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

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
        //String pk = separarValor(senhaBanco, 0);
        //String senha = concatSenha(pk, digitado.toString());
        String senhaCriptografada = criptografarMd5(digitado.toString());

        if (senhaCriptografada == null) {
            return false;
        }

        return compararSenhas(senhaCriptografada, senhaBanco);
    }

    /**
     * Encode a raw password into a valid MD5 password.
     *
     * @param userPk   The User PK.
     * @param password The password.
     * @implNote This algororithm is not secure and should be replaced by a more secure alternative (ex.: Argon2, BCrypt or PBKDF2).
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

    public static String criptografarMd5(String pwd) {
        if (md != null) {
            return new String(hexCodes(md.digest(pwd.getBytes())));
        }
        return null;
    }

    public boolean compararSenhas(String digitado, String esperado) {
        //return digitado.equals(separarValor(esperado, 1));
        return digitado.equalsIgnoreCase(esperado);
    }

    public String separarValor(String texto, int posicao) {
        String[] pk = texto.split(":");
        return pk[posicao];
    }

    public String concatSenha(String pk, String senha) {
        return pk + senha;
    }

}
