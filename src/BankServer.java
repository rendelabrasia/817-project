import java.util.HashMap;
import java.util.Map;
import java.io.*;
import java.net.*;

public class BankServer {
    private static final int PORT = 12345;
    private static Map<String, String> userDatabase = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Bank Server is listening on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ClientHandler(clientSocket).start();
            }
        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                String request;
                // Keep listening for client requests on the same connection
                while ((request = in.readLine()) != null) {
                    switch (request) {
                        case "REGISTER":
                            String username = in.readLine();
                            String password = in.readLine(); // Hash in a real system
                            String registrationResult = registerUser(username, password);
                            out.println(registrationResult);
                            break;
                        case "LOGIN":
                            username = in.readLine();
                            password = in.readLine();
                            boolean loggedIn = loginUser(username, password);
                            out.println(loggedIn ? "LOGGED IN" : "LOGIN FAILED");
                            break;
                        case "QUIT":
                            // Client wants to close the connection
                            return; // Exit the thread
                        default:
                            // Handle unknown requests or keep alive messages
                            break;
                    }
                }

            } catch (IOException ex) {
                System.out.println("Server exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }

        private synchronized String registerUser(String username, String password) {
            if (userDatabase.containsKey(username)) {
                // User already exists
                return "ERROR: User already exists. Please try a different username.";
            } else {
                // Here is where you would hash the password in a real system
                userDatabase.put(username, password);
                // Registration successful
                return "SUCCESS: User registered successfully.";
            }
        }

        private synchronized boolean loginUser(String username, String password) {

            String storedPassword = userDatabase.get(username);
            return storedPassword != null && storedPassword.equals(password);
        }
    }
}
