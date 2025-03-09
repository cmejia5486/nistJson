package nist.main; 

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import nist.Functions.JsonProcessor;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The {@code NistJsonGUI} class provides a graphical user interface for processing JSON files 
 * containing vulnerability data from the National Vulnerability Database (NVD).
 * It allows users to select directories for input and output, input start and end years,
 * and define keywords for processing the JSON data. The results are exported to CSV files.
 */
public class NistJsonGUI extends JFrame {

    private JTextField startYearField;
    private JTextField endYearField;
    private JTextField keywordsField;
    private JButton processButton;
    private JButton restartButton; // Restart button
    private JButton selectJsonDirectoryButton; // Select directory button
    private JButton selectOutputDirectoryButton; // Select output directory button
    private JTextArea outputArea;
    private List<String> keywords;
    private File jsonDirectory; // Store the selected JSON directory
    private File outputDirectory; // Store the selected output directory

    /**
     * Constructs a new {@code NistJsonGUI} instance, initializing the graphical interface 
     * components and setting up the layout for the main application window.
     */
    public NistJsonGUI() {
        setTitle("NIST JSON Processor");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        setLocationRelativeTo(null); // Center the window on the screen

        // Panel for input fields
        JPanel inputPanel = new JPanel(new GridLayout(8, 2, 10, 10)); // Added extra row for the restart button
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Input fields
        inputPanel.add(new JLabel("Start Year:"));
        startYearField = new JTextField();
        inputPanel.add(startYearField);

        inputPanel.add(new JLabel("End Year:"));
        endYearField = new JTextField();
        inputPanel.add(endYearField);

        inputPanel.add(new JLabel("Keywords (comma separated):"));
        keywordsField = new JTextField();
        inputPanel.add(keywordsField);

        // Select JSON Directory button
        selectJsonDirectoryButton = new JButton("1. Select JSON Directory");
        selectJsonDirectoryButton.addActionListener(e -> selectJsonDirectory());
        inputPanel.add(selectJsonDirectoryButton);

        // Select Output Directory button
        selectOutputDirectoryButton = new JButton("2. Select Output Results Directory");
        selectOutputDirectoryButton.addActionListener(e -> selectOutputDirectory());
        inputPanel.add(selectOutputDirectoryButton);

        // Process button
        processButton = new JButton("3. Process JSON Data");
        processButton.addActionListener(e -> processJsonFiles());
        inputPanel.add(processButton);

        // Restart button
        restartButton = new JButton("4. Clear");
        restartButton.addActionListener(e -> resetApplication()); // Restart logic
        inputPanel.add(restartButton);

        // Output area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);

        // Adding components to the window
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Opens a directory chooser dialog that allows the user to select the directory 
     * where the JSON files are located.
     */
    private void selectJsonDirectory() {
        JFileChooser directoryChooser = new JFileChooser();
        directoryChooser.setDialogTitle("Select JSON Files Directory");
        directoryChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = directoryChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            jsonDirectory = directoryChooser.getSelectedFile();
            outputArea.append("Selected JSON directory: " + jsonDirectory.getAbsolutePath() + "\n");
        }
    }

    /**
     * Opens a directory chooser dialog that allows the user to select the output directory 
     * where the resulting CSV files will be saved.
     */
    private void selectOutputDirectory() {
        JFileChooser directoryChooser = new JFileChooser();
        directoryChooser.setDialogTitle("Select Output Directory");
        directoryChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = directoryChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            outputDirectory = directoryChooser.getSelectedFile();
            outputArea.append("Selected output directory: " + outputDirectory.getAbsolutePath() + "\n");
        }
    }

    /**
     * Processes the JSON files from the selected directory for each year within the specified range.
     * It converts the processed data into CSV files, which are saved to the selected output directory.
     * The method also handles background processing to avoid blocking the UI.
     */
    private void processJsonFiles() {
        if (jsonDirectory == null || outputDirectory == null) {
            outputArea.append("Error: Please select both JSON directory and output directory.\n");
            return;
        }

        try {
            outputArea.append("Starting data processing...\n");
            int startYear = Integer.parseInt(startYearField.getText());
            int endYear = Integer.parseInt(endYearField.getText());

            String[] keywordArray = keywordsField.getText().split(",");
            keywords = new ArrayList<>();
            for (String keyword : keywordArray) {
                keywords.add(keyword.trim().toUpperCase());
            }

            ObjectMapper objectMapper = new ObjectMapper();
            JsonFactory jsonFactory = objectMapper.getFactory();

            SwingWorker<Void, String> worker = new SwingWorker<Void, String>() {
                @Override
                protected Void doInBackground() throws Exception {
                    for (int i = startYear; i <= endYear; i++) {
                        File file = new File(jsonDirectory, "nvdcve-1.1-" + i + ".json");

                        try (JsonParser parser = jsonFactory.createParser(file)) {
                            JsonProcessor jsonProcessor = new JsonProcessor(parser, keywords);
                            jsonProcessor.cveToCSV(new File(outputDirectory, i + "-cve.csv").getAbsolutePath(), true);
                            jsonProcessor.cweToCSV(new File(outputDirectory, i + "-cwe.csv").getAbsolutePath(), true);
                            jsonProcessor.softwareToCSV(new File(outputDirectory, i + "-swProducts.csv").getAbsolutePath(), true);

                            publish("Year processed: " + i + "\n");
                        } catch (IOException e) {
                            publish("Error processing file " + file.getName() + ": " + e.getMessage() + "\n");
                        }
                    }

                    File totalFile = new File(jsonDirectory, "Total.json");
                    try (JsonParser parser = jsonFactory.createParser(totalFile)) {
                        JsonProcessor jsonProcessor = new JsonProcessor(parser, keywords);
                        jsonProcessor.cveToCSV(new File(outputDirectory, "Total-cve.csv").getAbsolutePath(), true);
                        jsonProcessor.cweToCSV(new File(outputDirectory, "Total-cwe.csv").getAbsolutePath(), true);
                        jsonProcessor.softwareToCSV(new File(outputDirectory, "Total-swProducts.csv").getAbsolutePath(), true);
                        publish("The entire file was processed\n");
                    }

                    return null;
                }

                @Override
                protected void process(List<String> chunks) {
                    for (String chunk : chunks) {
                        outputArea.append(chunk);
                    }

                    outputArea.setCaretPosition(outputArea.getDocument().getLength());
                }

                @Override
                protected void done() {
                    outputArea.append("Process completed.\n");
                    JOptionPane.showMessageDialog(NistJsonGUI.this, "Process Completed", "Information", JOptionPane.INFORMATION_MESSAGE);
                }
            };

            worker.execute();

        } catch (Exception e) {
            outputArea.append("Error: " + e.getMessage() + "\n");
        }
    }

    /**
     * Resets the application's text fields and output area to their initial state.
     */
    private void resetApplication() {
        startYearField.setText("");
        endYearField.setText("");
        keywordsField.setText("");
        outputArea.setText("");
        keywords = new ArrayList<>();
        jsonDirectory = null;
        outputDirectory = null;
    }

    /**
     * Main method to launch the application.
     * 
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            NistJsonGUI frame = new NistJsonGUI();
            frame.setVisible(true);
        });
    }
}
