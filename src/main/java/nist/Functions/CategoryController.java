package nist.Functions;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import nist.Utility.Functions;
import nist.model.Category;
import nist.model.Entry;

public class CategoryController {

    private List<Category> summariesCwe;
    private static final String CWE_SUMMARY_PATH = "CweDefinitions/summary.txt";

    public CategoryController() {
        summariesCwe = loadCweSummaries();
    }

    // Load CWE summaries once during initialization
    private List<Category> loadCweSummaries() {
        List<Category> summaries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(new File(CWE_SUMMARY_PATH)))) {
            summaries = reader.lines()
                    .map(line -> line.split(";"))
                    .filter(parts -> parts.length == 2) // Ensure valid data format
                    .map(parts -> new Category(parts[0], parts[1]))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            System.err.println("Can't access cweSummary file: " + e.getMessage());
        }
        return summaries;
    }

    public Category fill(List<Entry> cveList, String cweId) {
        // Filter entries by CWE ID in parallel
        List<Entry> filteredEntries = cveList.parallelStream()
                .filter(entry -> cweId.equals(entry.getCategory()))
                .collect(Collectors.toList());

        // Calculate metrics using parallel streams
        DoubleAdder totalScore = new DoubleAdder();
        AtomicInteger criticalityForHealth = new AtomicInteger();
        filteredEntries.parallelStream().forEach(entry -> {
            totalScore.add(entry.getScore());
            if (entry.getRankingForHealth() == 1) {
                criticalityForHealth.incrementAndGet();
            }
        });

        int totalEntries = filteredEntries.size();
        int totalVulnerabilities = cveList.size();

        // Create and populate the category object
        Category category = new Category();
        category.setID(cweId);
        category.setEntries(filteredEntries);
        category.setNumber_of_criticality_for_health_vulnerabilities(criticalityForHealth.get());
        category.setNumber_of_vulnerabilities(totalEntries);
        category.setAverage_score(getAverageScore(totalScore.doubleValue(), totalEntries));
        category.setPresence(getPresence((double) totalEntries, totalVulnerabilities));
        category.setImpact(getImpact(category.getPresence(), category.getAverage_score()));
        category.setSummary(getCweSummary(cweId));

        return category;
    }

    private String getCweSummary(String id) {
        // Optimize summary lookup using streams
        return summariesCwe.stream()
                .filter(c -> id.equals(c.getID()))
                .map(Category::getSummary)
                .findFirst()
                .orElse("");
    }

    private Double getAverageScore(Double score, int cweLength) {
        return cweLength > 0 ? Functions.fourDecimalsDouble(score / cweLength) : 0.0;
    }

    private Double getPresence(double vulnerables, int totalVulnerabilities) {
        return totalVulnerabilities > 0 ? Functions.fourDecimalsDouble(vulnerables / totalVulnerabilities) : 0.0;
    }

    private Double getImpact(Double presence, Double averageScore) {
        return Functions.fourDecimalsDouble(presence * averageScore);
    }
}
