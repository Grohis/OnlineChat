package ru.otus.chat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatabaseAuthenticatedProvider implements AuthenticatedProvider {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/OnlineChat_DB";
    private static final String DB_USERNAME = "admin";
    private static final String DB_PASSWORD = "admin";

    private static final String SQL_AUTH = "SELECT u.username FROM users u WHERE u.login = ? AND u.password = ?";
    private static final String SQL_CHECK_LOGIN = "SELECT 1 FROM users WHERE login = ?";
    private static final String SQL_CHECK_USERNAME = "SELECT 1 FROM users WHERE username = ?";
    private static final String SQL_INSERT_USER = "INSERT INTO users (login, password, username) VALUES (?, ?, ?)";
    private static final String SQL_GET_ROLE =
            "SELECT r.role FROM roles r " +
                    "JOIN users_roles ur ON ur.role_id = r.id " +
                    "JOIN users u ON ur.user_id = u.id " +
                    "WHERE u.username = ?";

    private Server server;

    public DatabaseAuthenticatedProvider(Server server) {
        this.server = server;
    }

    @Override
    public void initialize() {
        System.out.println("initialize DatabaseAuthenticatedProvider");
    }

    @Override
    public boolean authenticate(ClientHandler clientHandler, String login, String password) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
             PreparedStatement statement = connection.prepareStatement(SQL_AUTH)) {

            statement.setString(1, login);
            statement.setString(2, password);

            try (ResultSet rs = statement.executeQuery()) {
                if (rs.next()) {
                    String username = rs.getString("username");
                    if (server.isUsernameBusy(username)) {
                        clientHandler.sendMsg("Данная учетная запись уже занята");
                        return false;
                    }

                    ClientHandler.Role role = getRoleByUsername(connection, username);
                    clientHandler.setRole(role);
                    clientHandler.setUsername(username);
                    server.subscribe(clientHandler);
                    clientHandler.sendMsg("/authok " + username);
                    return true;
                }
            }

            clientHandler.sendMsg("Некорректный логин/пароль");
        } catch (SQLException e) {
            e.printStackTrace();
            clientHandler.sendMsg("Ошибка аутентификации. Попробуйте позже.");
        }
        return false;
    }

    @Override
    public boolean registration(ClientHandler clientHandler, String login, String password, String username) {
        if (login.trim().length() < 3 || password.trim().length() < 3 || username.trim().length() < 3) {
            clientHandler.sendMsg("Логин, пароль и имя пользователя должны быть не короче 3 символов.");
            return false;
        }

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD)) {

            if (isLoginAlreadyExist(connection, login)) {
                clientHandler.sendMsg("Указанный логин уже занят");
                return false;
            }

            if (isUsernameAlreadyExist(connection, username)) {
                clientHandler.sendMsg("Указанное имя пользователя уже занято");
                return false;
            }

            try (PreparedStatement statement = connection.prepareStatement(SQL_INSERT_USER)) {
                statement.setString(1, login);
                statement.setString(2, password);
                statement.setString(3, username);
                statement.executeUpdate();
            }

            clientHandler.setUsername(username);
            server.subscribe(clientHandler);
            clientHandler.sendMsg("/regok " + username);
            return true;

        } catch (SQLException e) {
            e.printStackTrace();
            clientHandler.sendMsg("Ошибка регистрации. Попробуйте позже.");
            return false;
        }
    }

    private boolean isLoginAlreadyExist(Connection connection, String login) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SQL_CHECK_LOGIN)) {
            statement.setString(1, login);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean isUsernameAlreadyExist(Connection connection, String username) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SQL_CHECK_USERNAME)) {
            statement.setString(1, username);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        }
    }

    private ClientHandler.Role getRoleByUsername(Connection connection, String username) {
        try (PreparedStatement statement = connection.prepareStatement(SQL_GET_ROLE)) {
            statement.setString(1, username);
            try (ResultSet rs = statement.executeQuery()) {
                if (rs.next()) {
                    String role = rs.getString("role");
                    if ("ADMIN".equalsIgnoreCase(role)) {
                        return ClientHandler.Role.ADMIN;
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ClientHandler.Role.USER;
    }
}
