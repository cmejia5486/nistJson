/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.Functions;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import nist.Utility.Functions;
import nist.model.Entry;

/**
 *
 * @author Carlos
 */
public class EntryController {

    private Entry entry;
    private String descriptionTmp;
    private String summaryTmp;
    private String IdVulnerabilityTmp;
    List<String> exclutions;
    List<Entry> healthValues;
    private final String exclutionPath;
    private final String healthPath;

    public Entry getEntry() {
        return entry;
    }

    public void setEntry(Entry entry) {
        this.entry = entry;
    }

    public EntryController() {
        exclutions = new ArrayList<>();
        healthValues = new ArrayList<>();
        exclutionPath = "Exclutions/exclutions.txt";
        healthPath = "Health/metrics.csv";
        obtainExclutions();
        obtainHealthranking();
    }

    private void obtainExclutions() {
        String[] parts;
        try {
            File inclutions = new File(exclutionPath);
            BufferedReader inputI = new BufferedReader(new FileReader(inclutions));
            String readLine = inputI.readLine();
            while (readLine != null) {
                parts = readLine.split(";");
                exclutions.add(parts[0]);
                readLine = inputI.readLine();
            }
            inputI.close();
        } catch (Exception e) {
            System.out.println("Can't access exclution file" + e);
        }
    }

    private void obtainHealthranking() {
        String[] parts;
        try {
            Integer b = -1;
            File healtRanking = new File(healthPath);
            BufferedReader inputI = new BufferedReader(new FileReader(healtRanking));
            String readLine = inputI.readLine();
            while (readLine != null) {
                b = b + 1;
                parts = readLine.split(";");
                //ommit headers
                if (b > 0) {
                    healthValues.add(new Entry(parts[0], Integer.parseInt(parts[1])));
                }
                readLine = inputI.readLine();
            }
            inputI.close();
        } catch (Exception e) {
            System.out.println("Can't access ranking file" + e);
        }
    }

    private Integer verifyKeyAndExclutions(List<String> keys) {
        Integer response = 0;
        //check if has keywords
        for (String key : keys) {
            if (summaryTmp.toUpperCase().contains(key)) {
                response = 1;
                break;
            }
        }
        //check exclutions
        for (String exclution : exclutions) {
            if (exclution.equals(IdVulnerabilityTmp)) {
                response = 0;
                break;
            }
        }
        return response;
    }

    public Entry fill(JsonObject obj, List<String> keys) {

        if (!getScore(obj).equals(-1D)) {
            summaryTmp = getSummary(obj);
            IdVulnerabilityTmp = getIdVulnerability(obj);
            //looks for keys in order to find vulnerabilities
            if (verifyKeyAndExclutions(keys).equals(1)) {
                entry = new Entry();
                entry.setID(IdVulnerabilityTmp);
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
                entry.setObtainUserPrivilege(getobtainUserPrivilege(obj));
                entry.setObtainOtherPrivilege(getobtainOtherPrivilege(obj));
                entry.setUserInteractionRequired(getuserInteractionRequired(obj));
                entry.setVulnerableSoftware(getVulnerableSoftware1(obj));
                entry.setCategory(getCategory(obj));
                entry.setRankingForHealth(getRankingforHealth(IdVulnerabilityTmp));
            } else {
                entry = null;
            }
        } else {
            entry = null;
        }
        return entry;
    }

    private String getIdVulnerability(JsonObject obj) {
        return Functions.CheckString(obj.get("cve").getAsJsonObject().get("CVE_data_meta").getAsJsonObject().get("ID").getAsString());

    }

    private String getCategory(JsonObject obj) {
        String response = "";
        JsonArray tmp = obj.get("cve").getAsJsonObject().get("problemtype").getAsJsonObject().get("problemtype_data").getAsJsonArray();
        JsonArray tmp1;
        for (JsonElement jsonElement : tmp) {
            tmp1 = jsonElement.getAsJsonObject().get("description").getAsJsonArray();
            if (tmp1 != null) {
                for (JsonElement jsonElement1 : tmp1) {
                    response = jsonElement1.getAsJsonObject().get("value").getAsString();
                }
            }
        }
        return response;
    }

    private String getSummary(JsonObject obj) {
        JsonArray tmp = obj.get("cve").getAsJsonObject().get("description").getAsJsonObject().getAsJsonArray("description_data");
        for (JsonElement jsonElement : tmp) {
            descriptionTmp = jsonElement.getAsJsonObject().get("value").getAsString();
        }
        return Functions.CheckString(descriptionTmp);
    }

    private Double getScore(JsonObject obj) {

        try {
            JsonElement impact = obj.get("impact").getAsJsonObject().get("baseMetricV2");
            if (impact == null) {
                return -1D;
            } else {
                return Functions.fourDecimalsDouble(Double.parseDouble(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("baseScore").getAsString()));
            }
        } catch (Exception e) {
            System.out.println("Error in getScore(): " + e);
            return -1D;
        }

    }

    private String getAccessVector(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("accessVector").getAsString());
    }

    private String getAccessComplexity(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("accessComplexity").getAsString());
    }

    private String getAuthentication(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("authentication").getAsString());
    }

    private String getConfidentiality(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("confidentialityImpact").getAsString());
    }

    private String getIntegrity(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("integrityImpact").getAsString());
    }

    private String getAvailability(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("cvssV2").getAsJsonObject().get("availabilityImpact").getAsString());
    }

    private Integer getObtainAllPrivilege(JsonObject obj) {
        if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainAllPrivilege").getAsString()).equals("")) {
            return 0;
        } else {
            if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainAllPrivilege").getAsString()).equals("false")) {
                return 0;
            } else {
                return 1;
            }
        }

    }

    private Integer getobtainUserPrivilege(JsonObject obj) {
        if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainUserPrivilege").getAsString()).equals("")) {
            return 0;
        } else {
            if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainUserPrivilege").getAsString()).equals("false")) {
                return 0;
            } else {
                return 1;
            }
        }

    }

    private Integer getobtainOtherPrivilege(JsonObject obj) {
        if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainOtherPrivilege").getAsString()).equals("")) {
            return 0;
        } else {
            if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("obtainOtherPrivilege").getAsString()).equals("false")) {
                return 0;
            } else {
                return 1;
            }
        }

    }

    private Integer getuserInteractionRequired(JsonObject obj) {
        if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("userInteractionRequired").getAsString()).equals("")) {
            return 0;
        } else {
            if (Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("userInteractionRequired").getAsString()).equals("false")) {
                return 0;
            } else {
                return 1;
            }
        }

    }

    private Double getExploitability(JsonObject obj) {

        try {
            return Functions.fourDecimalsDouble(Double.parseDouble(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("exploitabilityScore").getAsString()));
        } catch (Exception e) {
            System.out.println("Error in getExploitability(): " + e);
            return -0.00D;
        }

    }

    private Double getImpact(JsonObject obj) {

        try {
            return Functions.fourDecimalsDouble(Double.parseDouble(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("impactScore").getAsString()));
        } catch (Exception e) {
            System.out.println("Error in getImpact(): " + e);
            return -0D;
        }

    }

    private String getSeverity(JsonObject obj) {
        return Functions.CheckString(obj.get("impact").getAsJsonObject().get("baseMetricV2").getAsJsonObject().get("severity").getAsString());
    }

    private Integer getRankingforHealth(String id) {
        Integer response = -1;
        for (Entry healthValue : healthValues) {
            if (healthValue.getID().equals(id)) {
                response = healthValue.getRankingForHealth();
                break;
            }
        }
        return response;
    }

    private ArrayList<String> getVulnerableSoftware1(JsonObject obj) {
        HashSet<String> response = new HashSet<>();
        JsonArray tmp;
        JsonArray tmp1, tmp2;
        if (obj.get("configurations").getAsJsonObject() != null) {
            tmp = obj.get("configurations").getAsJsonObject().get("nodes").getAsJsonArray();
            if (tmp != null && tmp.size() > 0) {
                for (JsonElement jsonElement : tmp) {
                    if (jsonElement.getAsJsonObject().get("cpe_match") != null) {
                        tmp1 = jsonElement.getAsJsonObject().get("cpe_match").getAsJsonArray();
                        if (tmp1.size() > 0) {
                            for (JsonElement jsonElement1 : tmp1) {
                                response.add(jsonElement1.getAsJsonObject().get("cpe23Uri").getAsString());
                            }
                        }
                    } else {
                        tmp1 = jsonElement.getAsJsonObject().get("children").getAsJsonArray();
                        if (tmp1 != null && tmp1.size() > 0) {
                            for (JsonElement jsonElement1 : tmp1) {
                                tmp2 = jsonElement1.getAsJsonObject().get("cpe_match").getAsJsonArray();
                                if (tmp2 != null && tmp2.size() > 0) {
                                    for (JsonElement jsonElement2 : tmp2) {
                                        response.add(jsonElement2.getAsJsonObject().get("cpe23Uri").getAsString());
                                    }
                                }

                            }

                        }
                    }
                }
            }
        }

        return new ArrayList<>(response);
    }

}
