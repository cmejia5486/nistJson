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

    public void setCveEntries(List<Entry> cveEntries) {
        this.cveEntries = cveEntries;
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
        Integer i = 0;
        Double a, b;
        Set<String> uniqueProducts = new HashSet<String>();
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();

        sb.append("ENTRY; SUMMARY; ATTACK_VECTOR; ACCESS_COMPLEXITY; AUTHENTICATION; CONFIDENTIALITY; INTEGRITY; AVAILABILITY; ;EXPLOITABILITY; OBTAIN_ALL_PRIVILLEGE; OBTAIN_USER_PRIVILLEGE; OBTAIN_OTHER_PRIVILLEGE; USER_INTERACTION_REQUIRED; SCORE; PRODUCTS_AFFECTED; PRESENCE; IMPACT; CRITICITY_FOR_HEALTH \n");
        //generate total products
        for (Entry cveEntry : cveEntries) {
            for (String vunerableSoftware : cveEntry.getVulnerableSoftware()) {
                uniqueProducts.add(vunerableSoftware);
            }
        }

        for (Entry entry : cveEntries) {
            //acumulador total de filas para sacar el average de disponibility ;etc
            i = i + 1;
            // COL 1 (entry)
            sb.append(entry.getID());
            sb.append(";");

            // COL 2 (summary)
            sb.append(entry.getSummary().replace(";", ","));
            sb.append(";");

            // COL 4 (ATTACK_VECTOR)
            sb.append(entry.getAttackVector());
            sb.append(";");

            // COL 5 (ACCESS_COMPLEXITY)
            sb.append(entry.getAccessComplexity());
            sb.append(";");

            // COL 6 (USER_AUTHENTICATION)
            sb.append(entry.getAuthentication());
            sb.append(";");

            // COL 7 (CONFIDENTIALITY)
            sb.append(entry.getConfidentiality());
            sb.append(";");

            // COL 8 (INTEGRITY)
            sb.append(entry.getIntegrity());
            sb.append(";");

            // COL 9 (AVAILABILITY)
            sb.append(entry.getAvailability());
            sb.append(";");

            // COL 9 (EXPLOITABILITY)
            sb.append(entry.getExploitability());
            sb.append(";");

            // COL 9 (OBTAIN_ALL_PRIVILLEGE)
            sb.append(entry.getObtainAllPrivilege());
            sb.append(";");

            // COL 9 (OBTAIN_USER_PRIVILLEGE)
            sb.append(entry.getObtainUserPrivilege());
            sb.append(";");

            // COL 9 (OBTAIN_OTHER_PRIVILLEGE)
            sb.append(entry.getObtainOtherPrivilege());
            sb.append(";");

            // COL 9 (USER_INTERACTION_REQUIRED)
            sb.append(entry.getUserInteractionRequired());
            sb.append(";");

            // COL 3 (SCORE)
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
            sb.append(entry.getRankingForHealth() + "");
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
        Integer i = 0;
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("CATEGORY; SUMMARY; NUMBER_OF_VULNERABILITIES; AVERAGE_SCORE; PRESENCE; IMPACT \n");

        for (Category c : cweCategories) {

            //acumulador total de filas para sacar el average de disponibility ;etc
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
            // COL 4 (average_score)
            sb.append((c.getAverage_score() + "").replace(".", ","));
            sb.append(";");

            // COL 5 (presence)
            sb.append(df.format(BigDecimal.valueOf(c.getPresence())).replace(".", ","));
            sb.append(";");

            // COL 6 (impact)
            sb.append(df.format(BigDecimal.valueOf(c.getImpact())).replace(".", ","));
            sb.append(";\n");
        }

        sb.append(
                "\n");
        sb.append(
                "\n");
        sb.append(
                "TOTAL PRODUCTS; " + i);

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
