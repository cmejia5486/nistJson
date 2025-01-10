package nist.Functions;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.text.DecimalFormat;
import java.util.*;
import nist.model.Category;
import nist.model.Entry;
import org.apache.commons.io.FileUtils;

public class JsonProcessor {

    private final JsonParser parser; // JsonParser para procesamiento por streaming
    private final List<String> keys;
    private final EntryController entryController;
    private final CategoryController categoryController;

    private final List<Entry> cveEntries;
    private final List<Category> cweCategories;
    private final Set<String> cwesHash;

    public JsonProcessor(JsonParser parser, List<String> keys) {
        this.parser = parser;
        this.keys = keys;
        this.entryController = new EntryController();
        this.categoryController = new CategoryController();
        this.cveEntries = new ArrayList<>();
        this.cweCategories = new ArrayList<>();
        this.cwesHash = new HashSet<>();
        iterateVulnerabilities();
        fillCweCategories();
    }

    private void iterateVulnerabilities() {
        try {
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String fieldName = parser.getCurrentName();
                if ("CVE_Items".equals(fieldName)) {
                    parser.nextToken(); // Avanza al inicio del array
                    while (parser.nextToken() != JsonToken.END_ARRAY) {
                        processVulnerability();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error while iterating vulnerabilities: " + e.getMessage());
        }
    }

    private void processVulnerability() {
        try {
            Entry entry = entryController.fill(parser.readValueAsTree(), keys);
            if (entry != null) {
                cwesHash.add(entry.getCategory());
                cveEntries.add(entry);
            }
        } catch (IOException e) {
            System.err.println("Error processing vulnerability: " + e.getMessage());
        }
    }

    private void fillCweCategories() {
        cwesHash.forEach(cwe -> cweCategories.add(categoryController.fill(cveEntries, cwe)));
    }

    public void cveToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        Set<String> uniqueProducts = new HashSet<>();
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();

        sb.append("ENTRY;SUMMARY;ACCESS_COMPLEXITY;AUTHENTICATION;CONFIDENTIALITY;INTEGRITY;AVAILABILITY;EXPLOITABILITY;SCORE;PRODUCTS_AFFECTED;PRESENCE;IMPACT;CRITICALITY_FOR_HEALTH;CATEGORY;YEAR\n");

        for (Entry entry : cveEntries) {
            uniqueProducts.addAll(entry.getVulnerableSoftware());

            sb.append(entry.getId()).append(";")
                    .append(entry.getSummary().replace(";", ",")).append(";")
                    .append(entry.getAccessComplexity()).append(";")
                    .append(entry.getAuthentication()).append(";")
                    .append(entry.getConfidentiality()).append(";")
                    .append(entry.getIntegrity()).append(";")
                    .append(entry.getAvailability()).append(";")
                    .append(df.format(entry.getExploitability()).replace(".", ",")).append(";")
                    .append(df.format(entry.getScore()).replace(".", ",")).append(";")
                    .append(entry.getVulnerableSoftware().size()).append(";")
                    .append(df.format((double) entry.getVulnerableSoftware().size() / uniqueProducts.size()).replace(".", ",")).append(";")
                    .append(df.format(entry.getScore() * entry.getVulnerableSoftware().size() / uniqueProducts.size()).replace(".", ",")).append(";");

            String criticality = entry.getRankingForHealth() == 0 ? "NO" :
                                 entry.getRankingForHealth() == 1 ? "YES" : "No sabe";
            sb.append(criticality).append(";")
                    .append(entry.getCategory()).append(";")
                    .append(entry.getId().split("-")[1]).append("\n");
        }

        sb.append("\nTOTAL PRODUCTS;").append(uniqueProducts.size());
        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    public void cweToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("CATEGORY;SUMMARY;NUMBER_OF_VULNERABILITIES;NUMBER_OF_VULNERABILITIES_WITH_CRITICALITY_FOR_HEALTH;AVERAGE_SCORE;PRESENCE;IMPACT;VULNERABLE_SOFTWARE\n");

        int totalVulnerabilities = 0;
        for (Category category : cweCategories) {
            sb.append(category.getID()).append(";")
                    .append(category.getSummary().replace(";", ",")).append(";")
                    .append(category.getNumber_of_vulnerabilities()).append(";")
                    .append(category.getNumber_of_criticality_for_health_vulnerabilities()).append(";")
                    .append(df.format(category.getAverage_score()).replace(".", ",")).append(";")
                    .append(df.format(category.getPresence()).replace(".", ",")).append(";")
                    .append(df.format(category.getImpact()).replace(".", ",")).append(";");

            Set<String> uniqueSoftware = new HashSet<>();
            category.getEntries().forEach(entry -> uniqueSoftware.addAll(entry.getVulnerableSoftware()));
            sb.append(uniqueSoftware.size()).append("\n");

            totalVulnerabilities += category.getNumber_of_vulnerabilities();
        }

        sb.append("\nTOTAL VULNERABILITIES;").append(totalVulnerabilities);
        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    public void softwareToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        Map<String, Integer> softwareCounts = new HashMap<>();
        Map<String, Integer> criticalCounts = new HashMap<>();

        for (Category category : cweCategories) {
            for (Entry entry : category.getEntries()) {
                for (String software : entry.getVulnerableSoftware()) {
                    softwareCounts.put(software, softwareCounts.getOrDefault(software, 0) + 1);
                    if (entry.getRankingForHealth() == 1) {
                        criticalCounts.put(software, criticalCounts.getOrDefault(software, 0) + 1);
                    }
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SOFTWARE_PRODUCT;NUMBER_OF_VULNERABILITIES;NUMBER_OF_CRITICAL_VULNERABILITIES\n");
        softwareCounts.forEach((product, count) -> {
            int criticalCount = criticalCounts.getOrDefault(product, 0);
            sb.append(product).append(";").append(count).append(";").append(criticalCount).append("\n");
        });

        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    private void writeToFile(String namefile, String content, boolean removeFileIfExists) throws IOException {
        File file = new File(namefile);
        if (removeFileIfExists && file.exists()) {
            file.delete();
        }
        FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
    }
}
