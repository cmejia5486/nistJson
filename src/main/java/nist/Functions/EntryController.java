package nist.Functions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import nist.Utility.Functions;
import nist.model.Entry;

/**
 * Controller responsible for processing and mapping JSON vulnerability data
 * into {@link Entry} objects. This class filters entries based on exclusion
 * lists and health rankings
 * @author Carlos
 * @version 1.0
 */
public class EntryController {

    /**
     * Stores the currently processed entry.
     */
    private Entry entry;
    /**
     * Temporary variables used during processing.
     */
    private String descriptionTmp;
    private String summaryTmp;
    private String IdVulnerabilityTmp;
    /**
     * List of excluded vulnerabilities.
     */
    private List<String> exclusions;
    /**
     * List of health-related vulnerability rankings.
     */
    private List<Entry> healthValues;
    /**
     * Path to the exclusions file.
     */
    private final String exclusionPath;
    /**
     * Path to the health rankings file.
     */
    private final String healthPath;

    /**
     * ObjectMapper for JSON processing using Jackson.
     */
    private final ObjectMapper objectMapper = new ObjectMapper(); // Jackson ObjectMapper

    /**
     * Retrieves the currently processed entry.
     *
     * @return The {@link Entry} object being processed.
     */
    public Entry getEntry() {
        return entry;
    }

    /**
     * Sets the entry object.
     *
     * @param entry The {@link Entry} object to set.
     */
    public void setEntry(Entry entry) {
        this.entry = entry;
    }

    /**
     * Initializes the EntryController, loading exclusions and health rankings.
     */
    public EntryController() {
        exclusions = new ArrayList<>();
        healthValues = new ArrayList<>();
        exclusionPath = "Exclusions/exclusions.txt";
        healthPath = "Critical/metrics.csv";
        obtainExclusions();
        obtainHealthranking();
    }

    /**
     * Loads the exclusion list from the specified file.
     */
    private void obtainExclusions() {
        String[] parts;
        try {
            File inclutions = new File(exclusionPath);
            BufferedReader inputI = new BufferedReader(new FileReader(inclutions));
            String readLine = inputI.readLine();
            while (readLine != null) {
                parts = readLine.split(";");
                exclusions.add(parts[0]);
                readLine = inputI.readLine();
            }
            inputI.close();
        } catch (Exception e) {
            System.out.println("Can't access exclusion file" + e);
        }
    }

    /**
     * Loads the health ranking data from the specified file.
     */
    private void obtainHealthranking() {
        String[] parts;
        try {
            int b = -1;
            File healthRanking = new File(healthPath);
            BufferedReader inputI = new BufferedReader(new FileReader(healthRanking));
            String readLine = inputI.readLine();
            while (readLine != null) {
                b++;
                parts = readLine.split(";");
                // Omit headers
                if (b > 0) {
                    healthValues.add(new Entry(parts[0], Integer.parseInt(parts[1])));
                }
                readLine = inputI.readLine();
            }
            inputI.close();
        } catch (Exception e) {
            System.out.println("Can't access ranking file " + healthPath + ": " + e);
        }
    }

    /**
     * Verifies if an entry contains a specified keyword and is not excluded.
     *
     * @param keys The list of keywords to check.
     * @return 1 if the entry contains a keyword and is not excluded, otherwise
     * 0.
     */
    private Integer verifyKeyAndExclusions(List<String> keys) {
        int response = 0;
        // Check if has keywords
        for (String key : keys) {
            if (summaryTmp.toUpperCase().contains(key)) {
                response = 1;
                break;
            }
        }
        // Check exclusions
        for (String exclusion : exclusions) {
            if (exclusion.equals(IdVulnerabilityTmp)) {
                response = 0;
                break;
            }
        }
        return response;
    }

    /**
     * Processes a JSON object to create an {@link Entry}.
     *
     * @param obj The JSON object containing vulnerability data.
     * @param keys The list of keywords used for filtering entries.
     * @return An {@link Entry} object if valid, otherwise {@code null}.
     */
    public Entry fill(ObjectNode obj, List<String> keys) {

        if (!getScore(obj).equals(-1D)) {
            summaryTmp = getSummary(obj);
            IdVulnerabilityTmp = getIdVulnerability(obj);
            // Looks for keys in order to find vulnerabilities
            if (verifyKeyAndExclusions(keys).equals(1)) {
                entry = new Entry();
                entry.setId(IdVulnerabilityTmp);
                entry.setSummary(summaryTmp);
                entry.setScore(getScore(obj));
                entry.setAttackVector(getAccessVector(obj));
                entry.setAccessComplexity(getAccessComplexity(obj));
                entry.setAuthentication(getAuthentication(obj));
                entry.setConfidentiality(getConfidentiality(obj));
                entry.setIntegrity(getIntegrity(obj));
                entry.setAvailability(getAvailability(obj));

                entry.setSeverity(getSeverity(obj));
                entry.setExploitability(getExploitability(obj));
                entry.setImpact(getImpact(obj));
                entry.setObtainAllPrivilege(getObtainAllPrivilege(obj));
                entry.setObtainUserPrivilege(getObtainUserPrivilege(obj));
                entry.setObtainOtherPrivilege(getObtainOtherPrivilege(obj));
                entry.setUserInteractionRequired(getUserInteractionRequired(obj));
                entry.setVulnerableSoftware(getVulnerableSoftware1(entry.getId(), obj));
                entry.setCategory(getCategory(obj));
                entry.setRankingForHealth(getRankingForHealth(IdVulnerabilityTmp));
            } else {
                entry = null;
            }
        } else {
            entry = null;
        }
        return entry;
    }

    /**
     * Retrieves the vulnerability ID from the JSON object.
     *
     * @param obj The JSON object.
     * @return The vulnerability ID.
     */
    private String getIdVulnerability(ObjectNode obj) {
        return Functions.CheckString(obj.at("/cve/CVE_data_meta/ID").asText());
    }

    /**
     * Retrieves the category (CWE ID) from the JSON object.
     *
     * @param obj The JSON object.
     * @return The CWE ID.
     */
    private String getCategory(ObjectNode obj) {
        String response = "";
        ArrayNode problemTypeData = (ArrayNode) obj.at("/cve/problemtype/problemtype_data");
        for (JsonNode data : problemTypeData) {
            ArrayNode description = (ArrayNode) data.get("description");
            if (description != null) {
                for (JsonNode desc : description) {
                    response = desc.get("value").asText();
                }
            }
        }
        return response;
    }

    /**
     * Retrieves the vulnerability description.
     *
     * @param obj The JSON object.
     * @return The description of the vulnerability.
     */
    private String getSummary(ObjectNode obj) {
        ArrayNode descriptionData = (ArrayNode) obj.at("/cve/description/description_data");
        for (JsonNode data : descriptionData) {
            descriptionTmp = data.get("value").asText();
        }
        return Functions.CheckString(descriptionTmp);
    }

    /**
     * Retrieves the CVSS score of the vulnerability.
     *
     * @param obj The JSON object.
     * @return The CVSS score or -1 if unavailable.
     */
    private Double getScore(ObjectNode obj) {
        try {
            JsonNode impact = obj.at("/impact/baseMetricV2");
            if (impact.isMissingNode()) {
                return -1D;
            } else {
                return Functions.fourDecimalsDouble(impact.at("/cvssV2/baseScore").asDouble());
            }
        } catch (Exception e) {
            System.out.println("Error in getScore(): " + e);
            return -1D;
        }
    }

    /**
     * Additional helper methods for extracting attributes.
     */
    private String getAccessVector(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/accessVector").asText());
    }

    private String getAccessComplexity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/accessComplexity").asText());
    }

    private String getAuthentication(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/authentication").asText());
    }

    private String getConfidentiality(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/confidentialityImpact").asText());
    }

    private String getIntegrity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/integrityImpact").asText());
    }

    private String getAvailability(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/availabilityImpact").asText());
    }

    private Integer getObtainAllPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainAllPrivilege").asText());
    }

    private Integer getObtainUserPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainUserPrivilege").asText());
    }

    private Integer getObtainOtherPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainOtherPrivilege").asText());
    }

    private Integer getUserInteractionRequired(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/userInteractionRequired").asText());
    }

    private Double getExploitability(ObjectNode obj) {
        return Functions.fourDecimalsDouble(obj.at("/impact/baseMetricV2/exploitabilityScore").asDouble());
    }

    private Double getImpact(ObjectNode obj) {
        return Functions.fourDecimalsDouble(obj.at("/impact/baseMetricV2/impactScore").asDouble());
    }

    private String getSeverity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/severity").asText());
    }

    private Integer parseBooleanToInteger(String value) {
        return "true".equalsIgnoreCase(value) ? 1 : 0;
    }

    private Integer getRankingForHealth(String id) {
        for (Entry healthValue : healthValues) {
            if (healthValue.getId().equals(id)) {
                return healthValue.getRankingForHealth();
            }
        }
        return -1;
    }

    /**
     * Retrieves a list of affected software for the vulnerability.
     *
     * @param obj The JSON object.
     * @return A list of vulnerable software identifiers.
     */
    private ArrayList<String> getVulnerableSoftware1(String vulne, ObjectNode obj) {
        HashSet<String> response = new HashSet<>();
        ArrayNode nodes = (ArrayNode) obj.at("/configurations/nodes");
        if (nodes != null) {
            for (JsonNode node : nodes) {
                ArrayNode cpeMatch = (ArrayNode) node.get("cpe_match");
                if (cpeMatch != null) {
                    for (JsonNode match : cpeMatch) {
                        response.add(match.get("cpe23Uri").asText());
                    }
                }
                ArrayNode children = (ArrayNode) node.get("children");
                if (children != null) {
                    for (JsonNode child : children) {
                        ArrayNode childCpeMatch = (ArrayNode) child.get("cpe_match");
                        if (childCpeMatch != null) {
                            for (JsonNode match : childCpeMatch) {
                                response.add(match.get("cpe23Uri").asText());
                            }
                        }
                    }
                }
            }
        }
        return new ArrayList<>(response);
    }
}
