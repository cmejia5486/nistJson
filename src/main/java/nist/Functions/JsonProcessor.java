/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.Functions;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
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

/**
 *
 * @author Carlos
 */
public class JsonProcessor {

    private JsonObject json;
    private JsonArray vulnerabilities;
    private EntryController entryController;
    private CategoryController categoryController;

    private List<Entry> cveEntries;
    private List<Category> cweCategories;

    private HashSet<String> cwesHash;
    private List<String> keys;

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

    public JsonProcessor(JsonObject json, List<String> keys) {
        init();
        this.keys = keys;
        this.json = json;
        this.vulnerabilities = json.getAsJsonArray("CVE_Items");
        iterateVulnerabilities();
        fillCweCategories();
    }

    public JsonObject getJson() {
        return json;
    }

    public void setJson(JsonObject json) {
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

    //methods
    private void iterateVulnerabilities() {
        for (Integer i = 0; i < vulnerabilities.size(); i++) {
            vulnerabilities.get(i);
            fillcveEntries(vulnerabilities.get(i).getAsJsonObject());
        }
    }

    private void fillCweCategories() {
        for (String cwe : cwesHash) {
            cweCategories.add(categoryController.fill(cveEntries, cwe));
        }

    }

    private void fillcveEntries(JsonObject vuln) {
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
        Set<String> uniqueProducts = new HashSet<String>();
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();

        sb.append("ENTRY; SUMMARY; ACCESS_COMPLEXITY; AUTHENTICATION; CONFIDENTIALITY; INTEGRITY; AVAILABILITY; EXPLOITABILITY; SCORE; PRODUCTS_AFFECTED; PRESENCE; IMPACT; CRITICALITY_FOR_HEALTH; CATEGORY; YEAR \n");
        //generate total products
        for (Entry cveEntry : cveEntries) {
            for (String vunerableSoftware : cveEntry.getVulnerableSoftware()) {
                uniqueProducts.add(vunerableSoftware);
            }
        }

        for (Entry entry : cveEntries) {
            // COL 1 (entry)
            sb.append(entry.getID());
            sb.append(";");

            // COL 2 (summary)
            sb.append(entry.getSummary().replace(";", ","));
            sb.append(";");

            // COL 3 (ACCESS_COMPLEXITY)
            sb.append(entry.getAccessComplexity());
            sb.append(";");

            // COL 4 (USER_AUTHENTICATION)
            sb.append(entry.getAuthentication());
            sb.append(";");

            // COL 5 (CONFIDENTIALITY)
            sb.append(entry.getConfidentiality());
            sb.append(";");

            // COL 6 (INTEGRITY)
            sb.append(entry.getIntegrity());
            sb.append(";");

            // COL 7 (AVAILABILITY)
            sb.append(entry.getAvailability());
            sb.append(";");

            // COL 8 (EXPLOITABILITY)
            sb.append((entry.getExploitability() + "").replace(".", ","));
            sb.append(";");

            // COL 9 (SCORE)
            sb.append((entry.getScore() + "").replace(".", ","));
            sb.append(";");

            // COL 10 (prodducts affected)
            sb.append(entry.getVulnerableSoftware().size());
            sb.append(";");

            // COL 11 (presence)
            a = Double.parseDouble(entry.getVulnerableSoftware().size() + "");
            b = Double.parseDouble(uniqueProducts.size() + "");
            sb.append(df.format(BigDecimal.valueOf(a / b)).replace(".", ","));
            sb.append(";");

            // COL 12 (impact)
            sb.append(df.format(BigDecimal.valueOf(entry.getScore() * (a / b))).replace(".", ","));
            sb.append(";");

            // COL 13 (CRITICITY_FOR_HEALTH)
            if (entry.getRankingForHealth() == 0 || entry.getRankingForHealth() == 1) {
                if (entry.getRankingForHealth() == 0) {
                    criticality = "NO";
                }
                if (entry.getRankingForHealth() == 1) {
                    criticality = "YES";
                }
            } else {
                criticality = "No sabe";
            }

            sb.append(criticality + "");
            sb.append(";");

            // COL 14 (CATEGORY)
            sb.append(entry.getCategory() + "");
            sb.append(";");

            // COL 15 (YEAR)
            year = entry.getID().replace("CVE-", "");
            year = year.substring(0, year.indexOf("-"));
            sb.append(year + "");
            sb.append("\n");
        }

        sb.append(
                "\n");
        sb.append(
                "\n");
        sb.append(
                "TOTAL PRODUCTS; " + uniqueProducts.size());

        String content = sb.toString();
        File file = new File(namefile);
        if (removeFileIfExists
                && file.exists()) {
            file.delete();
        }

        file.createNewFile();

        FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
    }

    public void cweToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        System.out.println("namefile: " + namefile);

        Integer i = 0;
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("CATEGORY; SUMMARY; NUMBER_OF_VULNERABILITIES; NUMBER_OF_VULNERAILITIES_WITH_CRITICALITY_FOR_HEALTH; AVERAGE_SCORE; PRESENCE; IMPACT; VULNERABLE_SOFTWARE \n");

        for (Category c : cweCategories) {

            // COL 1 (category)
            sb.append(c.getID());
            sb.append(";");

            // COL 2 (summary)
            sb.append(c.getSummary().replace(";", ","));
            sb.append(";");

            // COL 3 (number_of_vulnerabilities)
            sb.append((c.getNumber_of_vulnerabilities() + "").replace(".", ","));
            sb.append(";");
            i = i + c.getNumber_of_vulnerabilities();

            // COL 4 (NUMBER_OF_VULNERAILITIES_WITH_CRITICALITY_FOR_HEALTH)
            sb.append(c.getNumber_of_criticality_for_health_vulnerabilities());
            sb.append(";");

            // COL 5 (average_score)
            sb.append((c.getAverage_score() + "").replace(".", ","));
            sb.append(";");

            // COL 6 (presence)
            sb.append(df.format(BigDecimal.valueOf(c.getPresence())).replace(".", ","));
            sb.append(";");

            // COL 7 (impact)
            sb.append(df.format(BigDecimal.valueOf(c.getImpact())).replace(".", ","));

            // COL 8 (vulnerable_software)
            //calcula los productos software afectados por categoría
            HashSet<String> response = new HashSet<>();
            c.getEntries().forEach((entry) -> {
                entry.getVulnerableSoftware().forEach((product) -> {
                    response.add(product);
                });
            });
            int respuesta = response.size();
            sb.append(";" + respuesta);
            //fin calcula los productos software afectados por categoría

            sb.append("\n");
        }

        sb.append(
                "\n");
        sb.append(
                "\n");
        sb.append(
                "TOTAL VULNERABILITIES; " + i);

        String content = sb.toString();
        File file = new File(namefile);
        if (removeFileIfExists
                && file.exists()) {
            file.delete();
        }

        file.createNewFile();

        FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
    }

    public void softwareToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        System.out.println("namefile: " + namefile);
        HashSet<String> response = new HashSet<>();
        Integer i = 0;
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("SOFTWARE_PRODUCT; NUMBER_OF_VULNERABILITIES; cve; NUMBER_OF_VULNERAILITIES_WITH_CRITICALITY_FOR_HEALTH; cve2 \n");

        // INICIO COL 1 PRODUCT NAMES
        for (Category c : cweCategories) {
            c.getEntries().forEach((entry) -> {
                entry.getVulnerableSoftware().forEach((product) -> {
                    // System.out.println("Modifico el sw: " + product);
                    product = product.replace(":*", "");
                    product = product.replace("cpe:2.3:h:", "");
                    product = product.replace("cpe:2.3:a:", "");
                    product = product.replace("cpe:2.3:o:", "");
                    String[] parts = product.split(":");
                    if (parts.length > 1) {
                        if (parts[1].contains("_")) {
                            parts[1] = parts[1].substring(0, parts[1].indexOf("_"));
                        }
                        product = parts[0] + ":" + parts[1];

                    }

                    // System.out.println("Product resultante: " + product);
                    response.add(product);
                });
            });
        }
        // FIN COL 1 PRODUCT NAMES

        for (String productName : response) {
            int contador = 0;
            int contador1 = 0;
            String v1 = "";
            String v2 = "";
            for (Category c : cweCategories) {
                for (Entry vulnerability : c.getEntries()) {
                    for (String software : vulnerability.getVulnerableSoftware()) {
                        if (software.contains(productName)) {
                            v1 = v1 + ", " + vulnerability.getID();
                            contador = contador + 1;
                            if (vulnerability.getRankingForHealth() == 1) {
                                v2 = v2 + ", " + vulnerability.getID();
                                contador1 = contador1 + 1;
                            }
                            break;
                        }
                    }
                }
            }
            // productName = productName.replace(":*", "");
            // productName = productName.replace("cpe:2.3:h:", "");
            // productName = productName.replace("cpe:2.3:a:", "");
            // productName = productName.replace("cpe:2.3:o:", "");

            // System.out.println("el v1 fue: "+v1);
            //System.out.println("el v2 fue: "+v2);
            sb.append((productName + ";"));
            sb.append((contador + ";"));
            sb.append((v1 + ";"));
            sb.append((contador1 + ";"));
            sb.append((v2 + "\n"));

            System.out.println("el software: " + productName + " se encuentra presente en: " + contador + " vulnerabilidades: " + v1);
        }

        String content = sb.toString();
        File file = new File(namefile);
        if (removeFileIfExists
                && file.exists()) {
            file.delete();
        }
        file.createNewFile();
        FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
    }
}
