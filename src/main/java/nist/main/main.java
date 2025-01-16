package nist.main;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import nist.Functions.JsonProcessor;

public class main {

    public static void main(String[] args) {
        try {
            System.out.println("Welcome to Nist Json: Open-Source Tool for Json Processing and Software Vulnerabilities Analysis Based on NIST NVD");
            List<String> keys = new ArrayList<>();
            keys.add("HEALTH");
            keys.add("MEDIC");

            // Crear ObjectMapper y JsonFactory
            ObjectMapper objectMapper = new ObjectMapper();
            JsonFactory jsonFactory = objectMapper.getFactory();

            for (int i = 2002; i < 2026; i++) {
                File file = new File("JsonData/nvdcve-1.1-" + i + ".json");

                // Crear JsonParser asociado al ObjectMapper
                try (JsonParser parser = jsonFactory.createParser(file)) {
                    // Crear y procesar con JsonProcessor
                    JsonProcessor jsonProcessor = new JsonProcessor(parser, keys);

                    // Exportar datos a CSV
                    jsonProcessor.cveToCSV("results/" + i + "-cve.csv", true);
                    jsonProcessor.cweToCSV("results/" + i + "-cwe.csv", true);
                    jsonProcessor.softwareToCSV("results/" + i + "-swProducts.csv", true);
                    System.out.println("year processed: "+i);
                } catch (IOException e) {
                    System.err.println("Error processing file " + file.getName() + ": " + e.getMessage());
                }
            }

            // Procesar archivo total
            File totalFile = new File("JsonData/Total.json");
            try (JsonParser parser = jsonFactory.createParser(totalFile)) {
                JsonProcessor jsonProcessor = new JsonProcessor(parser, keys);
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
