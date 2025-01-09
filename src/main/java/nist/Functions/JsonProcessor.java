package nist.Functions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import nist.model.Category;
import nist.model.Entry;
import org.apache.commons.io.FileUtils;

public class JsonProcessor {

    private JsonNode json; // Reemplaza JsonObject por JsonNode
    private ArrayNode vulnerabilities; // Reemplaza JsonArray por ArrayNode
    private EntryController entryController;
    private CategoryController categoryController;

    private List<Entry> cveEntries;
    private List<Category> cweCategories;

    private HashSet<String> cwesHash;
    private List<String> keys;

    private final ObjectMapper objectMapper = new ObjectMapper(); // Jackson ObjectMapper para parseo

    private void init() {
        keys = new ArrayList<>();
        cwesHash = new HashSet<>();
        cveEntries = new ArrayList<>();
        cweCategories = new ArrayList<>();
        entryController = new EntryController();
        categoryController = new CategoryController();
    }

    public JsonProcessor() {
        init();
    }

    public JsonProcessor(JsonNode json, List<String> keys) {
        init();
        this.keys = keys;
        this.json = json;
        this.vulnerabilities = (ArrayNode) json.get("CVE_Items"); // Obtener el array
        iterateVulnerabilities();
        fillCweCategories();
    }

    public JsonNode getJson() {
        return json;
    }

    public void setJson(JsonNode json) {
        this.json = json;
    }

    public List<Entry> getCveEntries() {
        return cveEntries;
    }

    public List<Category> getCweCategories() {
        return cweCategories;
    }

    public void setCweCategories(List<Category> cweCategories) {
        this.cweCategories = cweCategories;
    }

    // Métodos
    private void iterateVulnerabilities() {
        for (JsonNode vulnerability : vulnerabilities) {
            fillcveEntries((ObjectNode) vulnerability);
        }
    }

    private void fillCweCategories() {
        for (String cwe : cwesHash) {
            cweCategories.add(categoryController.fill(cveEntries, cwe));
        }
    }

    private void fillcveEntries(ObjectNode vuln) {
        Entry revisar = entryController.fill(vuln, keys);
        if (revisar != null) {
            cwesHash.add(revisar.getCategory());
            cveEntries.add(revisar);
        }
    }

    public void cveToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        Double a, b;
        String year = "";
        String criticality = "";
        Set<String> uniqueProducts = new HashSet<>();
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();

        sb.append("ENTRY; SUMMARY; ACCESS_COMPLEXITY; AUTHENTICATION; CONFIDENTIALITY; INTEGRITY; AVAILABILITY; EXPLOITABILITY; SCORE; PRODUCTS_AFFECTED; PRESENCE; IMPACT; CRITICALITY_FOR_HEALTH; CATEGORY; YEAR \n");

        // Generar productos únicos
        for (Entry cveEntry : cveEntries) {
            uniqueProducts.addAll(cveEntry.getVulnerableSoftware());
        }

        for (Entry entry : cveEntries) {
            sb.append(entry.getId()).append(";");
            sb.append(entry.getSummary().replace(";", ",")).append(";");
            sb.append(entry.getAccessComplexity()).append(";");
            sb.append(entry.getAuthentication()).append(";");
            sb.append(entry.getConfidentiality()).append(";");
            sb.append(entry.getIntegrity()).append(";");
            sb.append(entry.getAvailability()).append(";");
            sb.append((entry.getExploitability() + "").replace(".", ",")).append(";");
            sb.append((entry.getScore() + "").replace(".", ",")).append(";");
            sb.append(entry.getVulnerableSoftware().size()).append(";");

            a = (double) entry.getVulnerableSoftware().size();
            b = (double) uniqueProducts.size();
            sb.append(df.format(BigDecimal.valueOf(a / b)).replace(".", ",")).append(";");
            sb.append(df.format(BigDecimal.valueOf(entry.getScore() * (a / b))).replace(".", ",")).append(";");

            if (entry.getRankingForHealth() == 0 || entry.getRankingForHealth() == 1) {
                criticality = entry.getRankingForHealth() == 0 ? "NO" : "YES";
            } else {
                criticality = "No sabe";
            }
            sb.append(criticality).append(";");
            sb.append(entry.getCategory()).append(";");

            year = entry.getId().replace("CVE-", "").split("-")[0];
            sb.append(year).append("\n");
        }

        sb.append("\n\nTOTAL PRODUCTS; ").append(uniqueProducts.size());

        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    public void cweToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        System.out.println("namefile: " + namefile);

        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("CATEGORY; SUMMARY; NUMBER_OF_VULNERABILITIES; NUMBER_OF_VULNERABILITIES_WITH_CRITICALITY_FOR_HEALTH; AVERAGE_SCORE; PRESENCE; IMPACT; VULNERABLE_SOFTWARE \n");

        int totalVulnerabilities = 0;

        for (Category c : cweCategories) {
            sb.append(c.getID()).append(";");
            sb.append(c.getSummary().replace(";", ",")).append(";");
            sb.append((c.getNumber_of_vulnerabilities() + "").replace(".", ",")).append(";");
            totalVulnerabilities += c.getNumber_of_vulnerabilities();
            sb.append(c.getNumber_of_criticality_for_health_vulnerabilities()).append(";");
            sb.append((c.getAverage_score() + "").replace(".", ",")).append(";");
            sb.append(df.format(BigDecimal.valueOf(c.getPresence())).replace(".", ",")).append(";");
            sb.append(df.format(BigDecimal.valueOf(c.getImpact())).replace(".", ",")).append(";");

            Set<String> uniqueSoftware = new HashSet<>();
            c.getEntries().forEach(entry -> uniqueSoftware.addAll(entry.getVulnerableSoftware()));
            sb.append(uniqueSoftware.size()).append("\n");
        }

        sb.append("\n\nTOTAL VULNERABILITIES; ").append(totalVulnerabilities);

        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    public void softwareToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        System.out.println("namefile: " + namefile);
        HashSet<String> uniqueProducts = new HashSet<>();
        StringBuilder sb = new StringBuilder();
        sb.append("SOFTWARE_PRODUCT; NUMBER_OF_VULNERABILITIES; cve; NUMBER_OF_VULNERABILITIES_WITH_CRITICALITY_FOR_HEALTH; cve2 \n");

        for (Category c : cweCategories) {
            c.getEntries().forEach(entry -> uniqueProducts.addAll(entry.getVulnerableSoftware()));
        }

        for (String productName : uniqueProducts) {
            int count = 0, criticalCount = 0;
            StringBuilder cves = new StringBuilder(), criticalCves = new StringBuilder();

            for (Category c : cweCategories) {
                for (Entry e : c.getEntries()) {
                    if (e.getVulnerableSoftware().contains(productName)) {
                        cves.append(", ").append(e.getId());
                        count++;
                        if (e.getRankingForHealth() == 1) {
                            criticalCves.append(", ").append(e.getId());
                            criticalCount++;
                        }
                    }
                }
            }

            sb.append(productName).append(";");
            sb.append(count).append(";");
            sb.append(cves).append(";");
            sb.append(criticalCount).append(";");
            sb.append(criticalCves).append("\n");
        }

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
