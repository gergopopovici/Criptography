package edu.bbte.pgim2289.cryptography.backend;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;

public class TLSServer {
    public static void main(String[] args) {
        int port = 443;
        String htmlFilePath = "C:/egyetem/3harmadik ev/elso felev/Criptography/lab4/JavaJSSe/client/bnr_response.html";

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreFile = new FileInputStream("C:/egyetem/3harmadik ev/elso felev/Criptography/lab4/JavaJSSe/fake_bnr.jks")) {
                keyStore.load(keyStoreFile, "password".toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, "password".toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket()) {
                serverSocket.bind(new InetSocketAddress(port));
                System.out.println("Fake BNR server is running on port " + port);

                while (true) {
                    try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                        System.out.println("Client connected: " + clientSocket.getInetAddress());
                        handleClient(clientSocket, htmlFilePath);
                    } catch (SocketException se) {
                        System.err.println("Client connection dropped: " + se.getMessage());
                    } catch (IOException e) {
                        System.err.println("Error processing client request: " + e.getMessage());
                    }
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException |
                 KeyManagementException e) {
            System.err.println("Error starting server: " + e.getMessage());
        }
    }

    private static void handleClient(SSLSocket clientSocket, String htmlFilePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                System.out.println(line);
            }
            String htmlContent = Files.readString(Path.of(htmlFilePath));
            writer.write("HTTP/1.1 200 OK\r\n");
            writer.write("Content-Type: text/html\r\n");
            writer.write("Content-Length: " + htmlContent.length() + "\r\n");
            writer.write("\r\n");
            writer.write(htmlContent);
            writer.flush();
        }
    }
}
