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

/**
 * Controller responsible for managing CWE categories and calculating related statistics.
 * It loads CWE definitions and computes vulnerability metrics.
 * @author Carlos
 * @version 1.0
 */
public class CategoryController {

    /**
     * List of CWE categories with their descriptions.
     */
    private List<Category> summariesCwe;

    /**
     * Path to the file containing CWE definitions.
     */
    private static final String CWE_SUMMARY_PATH = "CweDefinitions/summary.txt";

    /**
     * Constructor that initializes the controller and loads CWE definitions.
     */
    public CategoryController() {
        summariesCwe = loadCweSummaries();
    }

    /**
     * Loads CWE definitions from a text file.
     *
     * @return A list of {@code Category} objects containing CWE IDs and descriptions.
     */
    private List<Category> loadCweSummaries() {
        List<Category> summaries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(new File(CWE_SUMMARY_PATH)))) {
            summaries = reader.lines()
                    .map(line -> line.split(";"))
                    .filter(parts -> parts.length == 2) // Ensures valid data format
                    .map(parts -> new Category(parts[0], parts[1]))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            System.err.println("Can't access CWE summary file: " + e.getMessage());
        }
        return summaries;
    }

    /**
     * Computes vulnerability metrics for a specific CWE category.
     *
     * @param cveList List of vulnerabilities (CVE).
     * @param cweId   ID of the CWE category to process.
     * @return A {@code Category} object containing the computed metrics.
     */
    public Category fill(List<Entry> cveList, String cweId) {
        // Filters vulnerabilities associated with the given CWE category
        List<Entry> filteredEntries = cveList.parallelStream()
                .filter(entry -> cweId.equals(entry.getCategory()))
                .collect(Collectors.toList());

        // Calculates metrics using parallel streams
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

        // Creates and populates the category object with computed data
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

    /**
     * Retrieves the description of a CWE category based on its ID.
     *
     * @param id The CWE category ID.
     * @return The CWE category description, or an empty string if not found.
     */
    private String getCweSummary(String id) {
        return summariesCwe.stream()
                .filter(c -> id.equals(c.getID()))
                .map(Category::getSummary)
                .findFirst()
                .orElse("");
    }

    /**
     * Computes the average score of vulnerabilities within the CWE category.
     *
     * @param score     Total sum of scores.
     * @param cweLength Number of vulnerabilities in the CWE category.
     * @return The average score, rounded to 4 decimal places.
     */
    private Double getAverageScore(Double score, int cweLength) {
        return cweLength > 0 ? Functions.fourDecimalsDouble(score / cweLength) : 0.0;
    }

    /**
     * Computes the presence of the CWE category within the total set of vulnerabilities.
     *
     * @param vulnerables         Number of vulnerabilities associated with the CWE category.
     * @param totalVulnerabilities Total number of analyzed vulnerabilities.
     * @return Presence value, rounded to 4 decimal places.
     */
    private Double getPresence(double vulnerables, int totalVulnerabilities) {
        return totalVulnerabilities > 0 ? Functions.fourDecimalsDouble(vulnerables / totalVulnerabilities) : 0.0;
    }

    /**
     * Computes the impact of the CWE category based on its presence and average score.
     *
     * @param presence     Presence value of the CWE category.
     * @param averageScore Average score of the CWE category.
     * @return Impact value, rounded to 4 decimal places.
     */
    private Double getImpact(Double presence, Double averageScore) {
        return Functions.fourDecimalsDouble(presence * averageScore);
    }
}
