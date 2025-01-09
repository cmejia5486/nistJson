/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.main;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import nist.Functions.JsonProcessor;
import nist.Utility.Functions;

/**
 *
 * @author Carlos
 */
public class main {

    public static void main(String[] args) {
        try {
            List<String> keys = new ArrayList<>();
            // Fill keywords for searching
            keys.add("HEALTH");
            keys.add("MEDIC");

            // Jackson's ObjectMapper instance for JSON parsing
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true); // Allow control chars
            objectMapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS, true); // Allow non-numeric numbers

            for (int i = 2002; i < 2026; i++) {
                // Load JSON file
                File file = new File("JsonData/nvdcve-1.1-" + i + ".json");
                JsonNode jsonObject = safeLoadJson(file, objectMapper);

                if (jsonObject == null) {
                    System.out.println("Skipping file due to JSON errors: " + file.getAbsolutePath());
                    continue;
                }

                // Create a JSON processor for handling data
                JsonProcessor jsonProcessor = new JsonProcessor(jsonObject, keys);

                // Export data to CSV format
                jsonProcessor.cveToCSV("results/" + i + "-cve.csv", true);
                jsonProcessor.cweToCSV("results/" + i + "-cwe.csv", true);
                jsonProcessor.softwareToCSV("results/" + i + "-swProducts.csv", true);
            }

            // Process the total file
            File totalFile = new File(Functions.FILETOTAL);
            JsonNode totalJsonObject = safeLoadJson(totalFile, objectMapper);

            if (totalJsonObject != null) {
                // Create a JSON processor for the total data
                JsonProcessor totalJsonProcessor = new JsonProcessor(totalJsonObject, keys);

                // Export total data to CSV format
                totalJsonProcessor.cveToCSV("results/Total-cve.csv", true);
                totalJsonProcessor.cweToCSV("results/Total-cwe.csv", true);
                totalJsonProcessor.softwareToCSV("results/Total-swProducts.csv", true);
            } else {
                System.out.println("Skipping total file due to JSON errors: " + totalFile.getAbsolutePath());
            }

        } catch (Exception e) {
            System.out.println("error: " + e);
        }
    }

    /**
     * Safely loads a JSON file with error handling for encoding and parsing issues.
     *
     * @param file the JSON file to load
     * @param objectMapper the Jackson ObjectMapper instance
     * @return the JsonNode representation of the file, or null if errors occur
     */
    private static JsonNode safeLoadJson(File file, ObjectMapper objectMapper) {
        try {
            // Preprocess the file to remove invalid UTF-8 characters
            File sanitizedFile = sanitizeFileEncoding(file);

            // Load and parse the JSON file
            try (InputStream inputStream = new FileInputStream(sanitizedFile);
                 InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
                return objectMapper.readTree(reader);
            }

        } catch (JsonParseException e) {
            System.err.println("Failed to parse JSON file: " + file.getAbsolutePath() + " - " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Failed to read file: " + file.getAbsolutePath() + " - " + e.getMessage());
        }
        return null;
    }

    /**
     * Sanitizes a JSON file by removing invalid UTF-8 characters and ensuring proper encoding.
     *
     * @param file the JSON file to sanitize
     * @return a new sanitized File instance
     * @throws IOException if an error occurs during file operations
     */
    private static File sanitizeFileEncoding(File file) throws IOException {
        Path sanitizedPath = Paths.get(file.getParent(), "sanitized_" + file.getName());

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(sanitizedPath.toFile()), StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                // Remove non-UTF-8 characters
                String sanitizedLine = line.replaceAll("[^\\x00-\\x7F]", "");
                writer.write(sanitizedLine);
                writer.newLine();
            }
        }

        return sanitizedPath.toFile();
    }
}
