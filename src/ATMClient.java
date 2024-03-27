import java.io.*;
import java.net.*;

public class ATMClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("Connected to the bank server");
            System.out.println("Do you want to (1) Register or (2) Login? (Enter 1 or 2)");
            String option = stdIn.readLine();

            if ("1".equals(option)) {
                boolean isRegistered = false;
                while (!isRegistered) {
                    System.out.println("Enter username for registration:");
                    String username = stdIn.readLine();
                    System.out.println("Enter password for registration:");
                    String password = stdIn.readLine();

                    out.println("REGISTER");
                    out.println(username);
                    out.println(password);

                    String serverResponse = in.readLine();
                    System.out.println(serverResponse); // Server response printed out to the console

                    // If the user already exists, re-prompt for registration details
                    if (!serverResponse.startsWith("ERROR")) {
                        isRegistered = true;
                    }
                }
            } else if ("2".equals(option)) {
                // Login process
                System.out.println("Enter username for login:");
                String username = stdIn.readLine();
                System.out.println("Enter password for login:");
                String password = stdIn.readLine();

                out.println("LOGIN");
                out.println(username);
                out.println(password);

                String serverResponse = in.readLine();
                System.out.println(serverResponse); // Should be "LOGGED IN" if successful
            }

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + SERVER_ADDRESS);
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    SERVER_ADDRESS + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
}
