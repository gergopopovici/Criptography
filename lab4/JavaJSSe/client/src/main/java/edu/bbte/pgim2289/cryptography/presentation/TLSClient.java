package edu.bbte.pgim2289.cryptography.presentation;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;

public class TLSClient {
    public static void main(String[] args) {
        String httpsURL = "https://bnr.ro/Home.aspx";
        String output = "bnr_response.html";
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            URL url = new URL(httpsURL);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();

            System.out.println("Certificate Information:");
            Certificate[] certs = connection.getServerCertificates();
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    System.out.println("Subject: " + x509Cert.getSubjectDN());
                    System.out.println("Issuer: " + x509Cert.getIssuerDN());
                    System.out.println("Serial Number: " + x509Cert.getSerialNumber());
                    System.out.println("Valid From: " + x509Cert.getNotBefore());
                    System.out.println("Valid Until: " + x509Cert.getNotAfter());
                    System.out.println("Public Key: " + x509Cert.getPublicKey());
                    System.out.println("Version: " + x509Cert.getVersion());
                }
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new java.io.FileWriter(output));
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.write("\n");
            }
            reader.close();
            writer.close();
        } catch (KeyManagementException | NoSuchAlgorithmException | IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}