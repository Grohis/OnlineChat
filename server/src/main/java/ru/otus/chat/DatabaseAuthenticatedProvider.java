package ru.otus.chat;

import java.sql.*;
import ru.otus.chat.ClientHandler;

public class DatabaseAuthenticatedProvider implements AuthenticatedProvider {

    private Server server;
    private Connection connection;

    public DatabaseAuthenticatedProvider(Server server) {
        this.server = server;
    }

    @Override
    public void initialize() {
        try {
            Class.forName("org.postgresql.Driver");
            connection = DriverManager.getConnection(
                    "jdbc:postgresql://localhost:5432/OnlineChat_DB",
                    "admin",
                    "admin"
            );
            System.out.println("PostgreSQL подключение установлено!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getUsernameByLoginAndPassword(String login, String password) {
        String sql = "SELECT u.username FROM users u WHERE u.login = ? AND u.password = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, login);
            stmt.setString(2, password);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("username");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    private boolean isLoginAlreadyExist(String login) {
        String sql = "SELECT 1 FROM users WHERE login = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, login);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean isUsernameAlreadyExist(String username) {
        String sql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private ClientHandler.Role getRoleByUsername(String username) {
        String sql = "SELECT r.role_name FROM roles r " +
                "JOIN users_roles ur ON r.id = ur.role_id " +
                "JOIN users u ON ur.user_id = u.id " +
                "WHERE u.username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String roleName = rs.getString("role_name");
                return ClientHandler.Role.valueOf(roleName.toUpperCase());
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return ClientHandler.Role.USER;
    }

    @Override
    public boolean authenticate(ClientHandler clientHandler, String login, String password) {
        String authUsername = getUsernameByLoginAndPassword(login, password);
        if (authUsername == null) {
            clientHandler.sendMsg("Некорректный логин/пароль");
            return false;
        }

        if (server.isUsernameBusy(authUsername)) {
            clientHandler.sendMsg("Данная учетная запись уже занята");
            return false;
        }

        ClientHandler.Role role = getRoleByUsername(authUsername);
        clientHandler.setRole(role);

        clientHandler.setUsername(authUsername);
        server.subscribe(clientHandler);
        clientHandler.sendMsg("/authok " + authUsername);
        return true;
    }

    @Override
    public boolean registration(ClientHandler clientHandler, String login, String password, String username) {
        if (login.trim().length() < 3 || password.trim().length() < 3 || username.trim().length() < 3) {
            clientHandler.sendMsg("Логин 3+ символа, пароль 3+ символа, имя пользователя 3+ символа");
            return false;
        }

        if (isLoginAlreadyExist(login)) {
            clientHandler.sendMsg("Указанный логин уже занят");
            return false;
        }

        if (isUsernameAlreadyExist(username)) {
            clientHandler.sendMsg("Указанное имя пользователя уже занято");
            return false;
        }

        String sql = "INSERT INTO users (login, password, username) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, login);
            stmt.setString(2, password);
            stmt.setString(3, username);
            stmt.executeUpdate();

            assignDefaultRole(username);

            clientHandler.setUsername(username);
            server.subscribe(clientHandler);
            clientHandler.sendMsg("/regok " + username);
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void assignDefaultRole(String username) {
        try {
            String getUserIdSql = "SELECT id FROM users WHERE username = ?";
            PreparedStatement stmt1 = connection.prepareStatement(getUserIdSql);
            stmt1.setString(1, username);
            ResultSet rs = stmt1.executeQuery();
            if (rs.next()) {
                int userId = rs.getInt("id");

                String getRoleIdSql = "SELECT id FROM roles WHERE role_name = 'USER'";
                PreparedStatement stmt2 = connection.prepareStatement(getRoleIdSql);
                ResultSet rs2 = stmt2.executeQuery();

                if (rs2.next()) {
                    int roleId = rs2.getInt("id");

                    String insertSql = "INSERT INTO users_roles (user_id, role_id) VALUES (?, ?)";
                    PreparedStatement stmt3 = connection.prepareStatement(insertSql);
                    stmt3.setInt(1, userId);
                    stmt3.setInt(2, roleId);
                    stmt3.executeUpdate();
                }
                rs2.close();
                stmt2.close();
            }
            rs.close();
            stmt1.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
