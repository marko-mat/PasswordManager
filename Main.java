import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Main extends JFrame {
    // File where credentials are stored
    private static String FILE_NAME = "passwords.dat";
    private static final String KEY_FILE = "secret.key";
    private static SecretKey secretKey;
    private static Map<String, String> credentials = new HashMap<>();

    // GUI components
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextArea outputArea;

    public Main() {
        setTitle("Password Manager"); // Window title
        setSize(400, 250); // Window size
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(4, 1));

        // Input Panel (for username & password)
        JPanel inputPanel = new JPanel(new GridLayout(2, 2));
        inputPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        inputPanel.add(usernameField);
        inputPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        inputPanel.add(passwordField);
        add(inputPanel);

        // Buttons Panel
        JPanel buttonPanel = new JPanel();
        JButton addButton = new JButton("Add Credential");
        JButton retrieveButton = new JButton("Retrieve Password");
        buttonPanel.add(addButton);
        buttonPanel.add(retrieveButton);
        add(buttonPanel);

        // Output Area (to show messages and retrieved passwords)
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(new JScrollPane(outputArea));

        // Load encryption key and stored credentials
        try {
            loadOrGenerateKey();
            loadCredentials();
        } catch (Exception e) {
            outputArea.setText("Error loading data!");
        }

        // Button Actions
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addOrRetrieveCredential(true); // Calls method to add credential
            }
        });

        retrieveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addOrRetrieveCredential(false); // Calls method to retrieve credential
            }
        });
    }

    // Handles adding or retrieving credentials
    private void addOrRetrieveCredential(boolean isAdding) {
        String username = usernameField.getText().trim(); // Get username input
        String password = new String(passwordField.getPassword()).trim(); // Get password input

        if (username.isEmpty()) {
            outputArea.setText("Username cannot be empty.");
            return;
        }

        if (isAdding) { // If user is adding a new credential
            if (password.isEmpty()) {
                outputArea.setText("Password cannot be empty when adding a credential.");
                return;
            }
            if (credentials.containsKey(username)) {
                outputArea.setText("Username already exists! Choose another.");
                return;
            }
            try {
                credentials.put(username, password);
                try (BufferedWriter bw = new BufferedWriter(new FileWriter(FILE_NAME, true))) {
                    bw.write(username + "::" + encrypt(password) + "\n");
                }
                outputArea.setText("Credential added successfully.");
                usernameField.setText("");
                passwordField.setText("");
            } catch (Exception ex) {
                outputArea.setText("Error saving credentials.");
            }
        } else { // If user is retrieving a password
            String retrievedPassword = credentials.get(username);
            if (retrievedPassword != null) {
                outputArea.setText("Password: " + retrievedPassword);
            } else {
                outputArea.setText("Username not found.");
            }
        }
    }

    // Loads an encryption key from file or generates a new one
    private static void loadOrGenerateKey() throws Exception {
        File keyFile = new File(KEY_FILE);
        if (keyFile.exists()) {
            byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
            secretKey = new SecretKeySpec(keyBytes, "AES");
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            secretKey = keyGen.generateKey();
            Files.write(keyFile.toPath(), secretKey.getEncoded());
        }
    }

    // Loads stored credentials from file
    private static void loadCredentials() throws Exception {
        File file = new File(FILE_NAME);
        if (file.exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    String[] parts = line.split("::", 2);
                    if (parts.length == 2) {
                        credentials.put(parts[0], decrypt(parts[1]));
                    }
                }
            }
        }
    }

    // Encrypts password using AES encryption
    private static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypts stored password
    private static String decrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted);
    }

    // Main method - launches the GUI
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Main().setVisible(true));
    }
}
