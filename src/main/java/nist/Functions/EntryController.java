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

public class EntryController {

    private Entry entry;
    private String descriptionTmp;
    private String summaryTmp;
    private String IdVulnerabilityTmp;
    private List<String> exclusions;
    private List<Entry> healthValues;
    private final String exclusionPath;
    private final String healthPath;

    private final ObjectMapper objectMapper = new ObjectMapper(); // Jackson ObjectMapper

    public Entry getEntry() {
        return entry;
    }

    public void setEntry(Entry entry) {
        this.entry = entry;
    }

    public EntryController() {
        exclusions = new ArrayList<>();
        healthValues = new ArrayList<>();
        exclusionPath = "Exclusions/exclusions.txt";
        healthPath = "Health/metrics.csv";
        obtainExclusions();
        obtainHealthranking();
    }

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
            System.out.println("Can't access ranking file " + healthPath+": "+ e);
        }
    }

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

    private String getIdVulnerability(ObjectNode obj) {
        return Functions.CheckString(obj.at("/cve/CVE_data_meta/ID").asText());
    }

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

    private String getSummary(ObjectNode obj) {
        ArrayNode descriptionData = (ArrayNode) obj.at("/cve/description/description_data");
        for (JsonNode data : descriptionData) {
            descriptionTmp = data.get("value").asText();
        }
        return Functions.CheckString(descriptionTmp);
    }

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
