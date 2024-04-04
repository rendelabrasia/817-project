import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ATMClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 15008;
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String MAC_ALGORITHM = "HmacSHA256"; 
    private static final String keyString = "mySimpleSharedKey";
    private static final byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
    private static final SecretKey sharedKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
    private static final SecretKey macKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), MAC_ALGORITHM);

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {
    
            System.out.println("Connected to the bank server.");
            if (!loginOrRegister(out, in, stdIn)) {
                return; // Stop execution if login/register fails
            }

            while (true) {
                System.out.println("\nSelect an action:");
                System.out.println("(3) View Balance, (4) Deposit Money, (5) Withdraw Money, (6) Quit");
                String userAction = stdIn.readLine();
    
                if ("6".equals(userAction)) {
                    out.println("QUIT");
                    System.out.println("Thank you for using the bank service.");
                    break; // Exit loop to end program
                }
    
                processUserAction(out, in, stdIn, userAction);
            }
    
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
    

    private static boolean loginOrRegister(PrintWriter out, BufferedReader in, BufferedReader stdIn)
            throws IOException {
        System.out.println("Do you want to (1) Register or (2) Login? (Enter 1 or 2)");
        String option = stdIn.readLine();

        if ("1".equals(option)) {
            return registerUser(out, in, stdIn);
        } else if ("2".equals(option)) {
            return loginUser(out, in, stdIn);
        } else {
            System.out.println("Invalid option.");
            return false;
        }
    }

    private static boolean registerUser(PrintWriter out, BufferedReader in, BufferedReader stdIn) throws IOException {
        System.out.println("Enter username for registration:");
        String username = stdIn.readLine();
        System.out.println("Enter password for registration:");
        String password = stdIn.readLine();

        out.println("REGISTER");
        out.println(username);
        out.println(password);

        String serverResponse = in.readLine();
        System.out.println(serverResponse);

        return !serverResponse.startsWith("ERROR");
    }

    private static boolean loginUser(PrintWriter out, BufferedReader in, BufferedReader stdIn) throws IOException {
        System.out.println("Enter username for login:");
        String username = stdIn.readLine();
        System.out.println("Enter password for login:");
        String password = stdIn.readLine();

        out.println("LOGIN");
        out.println(username);
        out.println(password);

        String serverResponse = in.readLine();
        System.out.println(serverResponse);

        return "LOGGED IN".equals(serverResponse);
    }

    private static void processUserAction(PrintWriter out, BufferedReader in, BufferedReader stdIn, String action)
            throws IOException {
        switch (action) {

            case "3": // VIEW BALANCE
                out.println("VIEW BALANCE");
                String encryptedResponse = in.readLine(); // Receive encrypted balance
                String receivedMAC = in.readLine(); // Receive MAC
                System.out.println("Received encrypted balance info: " + encryptedResponse); // For debugging
                try {
                    String decryptedResponse = decrypt(encryptedResponse, sharedKey);

                    // Verify MAC for integrity
                    if (verifyMAC(encryptedResponse, receivedMAC, macKey)) {
                        System.out.println("Decrypted balance info: " + decryptedResponse); // Show decrypted message
                        // logAction("VIEW BALANCE", "Requested");
                    } else {
                        System.out.println("Integrity check failed! Response might be tampered.");
                    }
                    
                } catch (Exception e) {
                    System.err.println("Decryption error: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case "4": // DEPOSIT
                System.out.println("Enter amount to deposit:");
                String amount = stdIn.readLine();
                out.println("DEPOSIT");
                out.println(amount);
                // Read the encrypted response from the server
                encryptedResponse = in.readLine();
                receivedMAC = in.readLine(); // Receive MAC
                System.out.println("Received encrypted deposit confirmation: " + encryptedResponse); // Print the encrypted message
                // Decrypt the response
                try {
                    String decryptedResponse = decrypt(encryptedResponse, sharedKey);

                    // Verify MAC for integrity
                    if (verifyMAC(encryptedResponse, receivedMAC, macKey)) {
                        System.out.println("Decrypted deposit confirmation: " + decryptedResponse); // Display the decrypted message
                    } else {
                        System.out.println("Integrity check failed! Response might be tampered.");
                    }
                    
                } catch (Exception e) {
                    System.err.println("Decryption error: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case "5": // WITHDRAW
                System.out.println("Enter amount to withdraw:");
                amount = stdIn.readLine();
                out.println("WITHDRAW");
                out.println(amount);
                // Read the encrypted response from the server
                encryptedResponse = in.readLine();
                receivedMAC = in.readLine(); // Receive MAC
                System.out.println("Received encrypted withdrawal confirmation: " + encryptedResponse); // Print the encrypted message
                // Decrypt the response
                try {
                    String decryptedResponse = decrypt(encryptedResponse, sharedKey);

                    // Verify MAC for integrity
                    if (verifyMAC(encryptedResponse, receivedMAC, macKey)) {
                        System.out.println("Decrypted withdrawal confirmation: " + decryptedResponse); // Display the decrypted message
                    } else {
                        System.out.println("Integrity check failed! Response might be tampered.");
                    }
                    
                } catch (Exception e) {
                    System.err.println("Decryption error: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            
        }

        // Read and display server response for valid actions
        System.out.println("\nReading Server Response....");
        String serverResponse = in.readLine();
        System.out.println("\nServer response received....");
        System.out.println(serverResponse);
        System.out.println("\nFunctionality Successful!");
    }

    private static void logAction(String action, String amount) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("audit_log.txt", true));
            writer.write(getCurrentDateTime() + " - " + action + ", Amount: $" + amount);
            writer.newLine();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getCurrentDateTime() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date();
        return formatter.format(date);
    }

    private static void performKeyDistributionProtocol(PrintWriter out, BufferedReader in) throws IOException {
        try {
            // Step 1: Generate client nonce (nonce_C) and send to server
            String nonce_C = generateNonce();
            out.println(encrypt(nonce_C, sharedKey));

            // Step 2: Receive server's nonce and decrypt it
            String encryptedNonce_S = in.readLine();
            String nonce_S = decrypt(encryptedNonce_S, sharedKey);

            // Step 3: Derive Master Secret from nonces
            SecretKey masterSecret = deriveMasterSecret(nonce_C, nonce_S, sharedKey);
            System.out.println("Master Secret established.");

            // Derive Data Encryption Key and MAC Key from Master Secret
            SecretKey[] keys = deriveKeysFromMasterSecret(masterSecret);
            SecretKey encryptionKey = keys[0];
            SecretKey macKey = keys[1];
            System.out.println("Data Encryption Key and MAC Key derived.");

            // Indicate completion
            System.out.println("KEY DISTRIBUTION COMPLETE");

        } catch (Exception e) {
            throw new IOException("Key distribution failed", e);
        }
    }

    private static String generateNonce() {
        // Securely generate and return a nonce
        return Long.toString(new SecureRandom().nextLong());
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(original);
    }

    private static SecretKey deriveMasterSecret(String nonce_C, String nonce_S, SecretKey sharedKey) throws Exception {
        // Derive Master Secret (example method, adjust as needed)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest((nonce_C + nonce_S).getBytes());
        return new SecretKeySpec(Arrays.copyOf(hash, 16), "AES"); // Using first 128 bits of hash
    }

    private static SecretKey[] deriveKeysFromMasterSecret(SecretKey masterSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(masterSecret.getEncoded());

        // Split the hash in half; use the first part for the encryption key, the second
        // part for the MAC key
        byte[] encryptionKeyBytes = Arrays.copyOfRange(hash, 0, hash.length / 2);
        byte[] macKeyBytes = Arrays.copyOfRange(hash, hash.length / 2, hash.length);

        // Create SecretKey objects from the byte arrays
        SecretKey encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");
        SecretKey macKey = new SecretKeySpec(macKeyBytes, "AES"); // Use "HmacSHA256" for HMAC operations

        return new SecretKey[] { encryptionKey, macKey };
    }

    private static boolean verifyMAC(String data, String receivedMAC, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(key);
        byte[] macBytes = mac.doFinal(data.getBytes());
        String calculatedMAC = Base64.getEncoder().encodeToString(macBytes);
        return calculatedMAC.equals(receivedMAC);
    }
}