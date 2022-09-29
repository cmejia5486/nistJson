/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.Functions;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import nist.Utility.Functions;
import nist.model.Category;
import nist.model.Entry;

/**
 *
 * @author Carlos
 */
public class CategoryController {

    private Category category;
    private List<Entry> entries;
    private List<Category> summariesCwe;
    private final String cweSummaryPath = "CweDefinitions/summary.txt";

    private void init() {
        summariesCwe = new ArrayList<>();
        category = new Category();
        obtainCweSummary();
    }

    private void obtainCweSummary() {
        String[] parts;
        try {
            File cweSummary = new File(cweSummaryPath);
            BufferedReader inputI = new BufferedReader(new FileReader(cweSummary));
            String readLine = inputI.readLine();
            while (readLine != null) {
                parts = readLine.split(";");
                summariesCwe.add(new Category(parts[0], parts[1]));
                readLine = inputI.readLine();
            }
            inputI.close();
        } catch (Exception e) {
            System.out.println("Can't access cweSummary file" + e);
        }
    }

    public CategoryController() {
        init();
    }

    public Category fill(List<Entry> cveList, String cweId) {
        String software = "";
        entries = new ArrayList<>();
        Double sum = 0D;
        Integer sumSalud = 0;
        category = new Category();
        for (Entry entry : cveList) {
            software = "";
            if (entry.getCategory().equals(cweId)) {
                entries.add(entry);
               // System.out.println("entry fue: " + entry);
                sum = sum + entry.getScore();
                if (entry.getRankingForHealth() == 1) {
                    sumSalud = sumSalud + 1;
                }
            }
        }
        category.setID(cweId);
        category.setEntries(entries);
        category.setNumber_of_criticality_for_health_vulnerabilities(sumSalud);
        category.setNumber_of_vulnerabilities(entries.size());
        category.setAverage_score(getAverageScore(sum, entries.size()));
        category.setPresence(getPresence(Double.parseDouble(entries.size() + ""), cveList.size()));
        category.setImpact(getImpact(category.getPresence(), category.getAverage_score()));
        category.setSummary(getCweSummary(cweId));
        return category;
    }

    private String getCweSummary(String id) {
        String response = "";
        for (Category c : summariesCwe) {
            if (c.getID().equals(id)) {
                response = c.getSummary();
                break;
            }
        }
        return response;
    }

    private Double getAverageScore(Double score, Integer cweLength) {
        return Functions.fourDecimalsDouble(score / cweLength);
    }

    private Double getPresence(Double vulnerables, Integer totalVulnerabilities) {
        return Functions.fourDecimalsDouble(vulnerables / totalVulnerabilities);
    }

    private Double getImpact(Double presence, Double averageScore) {
        return Functions.fourDecimalsDouble(presence * averageScore);
    }
}
