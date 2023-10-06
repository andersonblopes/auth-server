package com.lopessystem.authserver.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@NoArgsConstructor
@Entity
@Table(name = "sys_usuario", schema = "ish")
public class UserInfo {

    @EqualsAndHashCode.Include
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "pkusuario")
    private Integer id;

    @Column(name = "uuid")
    private UUID uuid;

    @Column(name = "usuario")
    private String name;

    @Column(name = "email")
    private String email;

    @Column(name = "login")
    private String login;

    @Column(name = "senha")
    private String password;

    @Column(name = "administrador")
    private Boolean administrator;

    @Column(name = "master")
    private Boolean master;

    @Column(name = "celular")
    private String cellphone;

    @Column(name = "cpf")
    private String cpf;

    @Column(name = "datanascimento")
    private LocalDate birthDate;

    @Column(name = "ativo")
    private Boolean active;

    @ManyToMany
    @JoinTable(
            name = "sys_perfil_usuario", schema = "ish",
            joinColumns = @JoinColumn(name = "fkusuario"),
            inverseJoinColumns = @JoinColumn(name = "fkperfil"))
    private Set<Role> roles;

    public String getPassword() {
        this.password = this.id + ":" + this.password;
        return password;
    }
}
