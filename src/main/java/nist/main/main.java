package nist.main;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import nist.Functions.JsonProcessor;

/**
 * The {@code main} class serves as the entry point for the NIST JSON 
 * processing tool. This open-source tool processes JSON files containing 
 * vulnerability data from the National Vulnerability Database (NVD) and 
 * exports relevant information into CSV format.
 *
 * <p>The tool processes JSON files for each year from 2002 to 2025, extracting 
 * information about vulnerabilities (CVE), weaknesses (CWE), and affected 
 * software products. Additionally, it processes a cumulative JSON file 
 * ("Total.json") containing all vulnerability data.
 *
 * <p>Processed CSV files are stored in the "results" directory.
 *
 * @author Carlos
 * @version 1.0
 */
public class main {

    /**
     * The main method serves as the entry point for processing JSON vulnerability files.
     * It reads and processes JSON data for each year in the range 2002-2025, as well 
     * as a cumulative dataset from "Total.json". Extracted data is stored in CSV format.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        try {
            System.out.println("Welcome to Nist Json: Open-Source Tool for Json Processing and Software Vulnerabilities Analysis Based on NIST NVD");
            System.out.println("\nEnter the start year to be analyzed");
            Scanner scanner = new Scanner(System.in);
            int startYear = scanner.nextInt();
            System.out.println("Enter the end year to be analyzed");
            int endYear = scanner.nextInt();
            // List of keywords used for processing vulnerabilities related to health and medicine
            System.out.println("Enter the number of keywords to read");
            int numberOfWords = scanner.nextInt();
            
            List<String> keys = new ArrayList<>();
            //keys.add("HEALTH");
            //keys.add("MEDIC");
            for (int i = 1; i <= numberOfWords; i++) {
            System.out.println("Enter keyword number "+i);
            keys.add(scanner.next());
            }
            scanner.close();
            // Create ObjectMapper and JsonFactory instances
            ObjectMapper objectMapper = new ObjectMapper();
            JsonFactory jsonFactory = objectMapper.getFactory();

            // Process JSON files for each year from start year to end year
            for (int i = startYear; i <= endYear; i++) {
                File file = new File("JsonData/nvdcve-1.1-" + i + ".json");

                // Create JsonParser associated with ObjectMapper
                try (JsonParser parser = jsonFactory.createParser(file)) {
                    // Create and process with JsonProcessor
                    JsonProcessor jsonProcessor = new JsonProcessor(parser, keys);

                    // Export data to CSV files
                    jsonProcessor.cveToCSV("results/" + i + "-cve.csv", true);
                    jsonProcessor.cweToCSV("results/" + i + "-cwe.csv", true);
                    jsonProcessor.softwareToCSV("results/" + i + "-swProducts.csv", true);
                    System.out.println("Year processed: " + i);
                } catch (IOException e) {
                    System.err.println("Error processing file " + file.getName() + ": " + e.getMessage());
                }
            }

            // Process the cumulative "Total.json" file
            File totalFile = new File("JsonData/Total.json");
            try (JsonParser parser = jsonFactory.createParser(totalFile)) {
                JsonProcessor jsonProcessor = new JsonProcessor(parser, keys);

                // Export cumulative data to CSV files
                jsonProcessor.cveToCSV("results/Total-cve.csv", true);
                jsonProcessor.cweToCSV("results/Total-cwe.csv", true);
                jsonProcessor.softwareToCSV("results/Total-swProducts.csv", true);
                System.out.println("The entire file was processed");
            }

        } catch (Exception e) {
            System.err.println("Error in main: " + e.getMessage());
        }
    }    
}
