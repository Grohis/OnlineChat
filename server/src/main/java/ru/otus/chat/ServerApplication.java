package ru.otus.chat;

public class ServerApplication {
    public static void main(String[] args) {
        try {
            new Server(8189).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}