package edu.bbte.pgim2289.cryptography.presentation;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TLSClient {
    public static void main(String[] args) {
        String httpsURL = "https://bnr.ro/Home.aspx";
        String output = "bnr_response.html";
        String trustStorePath = "C:/egyetem/3harmadik ev/elso felev/Criptography/lab4/JavaJSSe/truststore.jks";
        String trustStorePassword = "password";

        String expectedRealCN = "*.bnr.ro";

        try {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            URL url = new URL(httpsURL);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();

            Certificate[] serverCertificates = connection.getServerCertificates();
            boolean isRealServer = false;

            System.out.println("Certificate Information:");
            for (Certificate cert : serverCertificates) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;

                    String subjectDN = x509Cert.getSubjectX500Principal().getName();
                    String subjectCN = extractCN(subjectDN);

                    System.out.println("Subject: " + subjectDN);
                    System.out.println("Issuer: " + x509Cert.getIssuerX500Principal().getName());
                    System.out.println("Serial Number: " + x509Cert.getSerialNumber());
                    System.out.println("Valid From: " + x509Cert.getNotBefore());
                    System.out.println("Valid Until: " + x509Cert.getNotAfter());

                    if (expectedRealCN.equals(subjectCN)) {
                        isRealServer = true;
                        break;
                    }
                }
            }

            if (!isRealServer) {
                throw new SecurityException("Certificate validation failed. This may not be the authentic Romanian National Bank server!");
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new FileWriter(output));
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.write("\n");
            }
            reader.close();
            writer.close();
            System.out.println("HTML response saved to " + output);

        } catch (SecurityException e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("Warning: Potential man-in-the-middle attack detected!");
        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.out.println("Error: SSL handshake failed. Possible certificate mismatch!");
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException
                 | CertificateException | KeyManagementException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static String extractCN(String distinguishedName) {
        for (String part : distinguishedName.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }
}