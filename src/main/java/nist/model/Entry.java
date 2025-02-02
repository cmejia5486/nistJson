package nist.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents an <i>Entry</i> for a vulnerability in the NIST data feed.
 * Each entry contains detailed information about a specific vulnerability,
 * including its severity, impact, exploitability, and affected software.
 *
 * @author Carlos
 * @version 1.0
 */
public class Entry {

    /**
     * The unique identifier for the vulnerability (CVE ID).
     */
    private String id;

    /**
     * A brief summary describing the vulnerability.
     */
    private String summary;

    /**
     * The severity score of the vulnerability (CVSS score).
     */
    private double score;

    /**
     * The attack vector of the vulnerability (e.g., NETWORK, LOCAL).
     */
    private String attackVector;

    /**
     * The access complexity required to exploit the vulnerability.
     */
    private String accessComplexity;

    /**
     * The authentication level required to exploit the vulnerability.
     */
    private String authentication;

    /**
     * The impact on confidentiality if the vulnerability is exploited.
     */
    private String confidentiality;

    /**
     * The impact on integrity if the vulnerability is exploited.
     */
    private String integrity;

    /**
     * The impact on availability if the vulnerability is exploited.
     */
    private String availability;

    /**
     * The severity level of the vulnerability (e.g., LOW, MEDIUM, HIGH).
     */
    private String severity;

    /**
     * The exploitability score of the vulnerability.
     */
    private double exploitability;

    /**
     * The impact score of the vulnerability.
     */
    private double impact;

    /**
     * Indicates whether the vulnerability allows obtaining all privileges.
     */
    private Integer obtainAllPrivilege;

    /**
     * Indicates whether the vulnerability allows obtaining user privileges.
     */
    private Integer obtainUserPrivilege;

    /**
     * Indicates whether the vulnerability allows obtaining other privileges.
     */
    private Integer obtainOtherPrivilege;

    /**
     * Indicates whether user interaction is required to exploit the vulnerability.
     */
    private Integer userInteractionRequired;

    /**
     * The ranking of the vulnerability in relation to health-related systems.
     */
    private Integer rankingForHealth;

    /**
     * The category associated with the vulnerability.
     */
    private String category;

    /**
     * The list of software products affected by this vulnerability.
     */
    private final List<String> vulnerableSoftware;

    /**
     * Default constructor initializing an empty list of vulnerable software.
     */
    public Entry() {
        this.vulnerableSoftware = new CopyOnWriteArrayList<>();
    }

    /**
     * Constructs an {@code Entry} with a specified ID and health ranking.
     *
     * @param id      The unique identifier for the vulnerability.
     * @param ranking The ranking of the vulnerability for health-related systems.
     */
    public Entry(String id, Integer ranking) {
        this();
        this.id = id;
        this.rankingForHealth = ranking;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * Checks if the entry has an associated category.
     *
     * @return {@code true} if a category is assigned, otherwise {@code false}.
     */
    public boolean hasCategory() {
        return category != null && !category.isEmpty();
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public double getScore() {
        return score;
    }

    public void setScore(double score) {
        this.score = score;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public double getExploitability() {
        return exploitability;
    }

    public void setExploitability(double exploitability) {
        this.exploitability = exploitability;
    }

    public double getImpact() {
        return impact;
    }

    public void setImpact(double impact) {
        this.impact = impact;
    }

    public Integer getObtainAllPrivilege() {
        return obtainAllPrivilege;
    }

    public void setObtainAllPrivilege(Integer obtainAllPrivilege) {
        this.obtainAllPrivilege = obtainAllPrivilege;
    }

    public Integer getObtainUserPrivilege() {
        return obtainUserPrivilege;
    }

    public void setObtainUserPrivilege(Integer obtainUserPrivilege) {
        this.obtainUserPrivilege = obtainUserPrivilege;
    }

    public Integer getObtainOtherPrivilege() {
        return obtainOtherPrivilege;
    }

    public void setObtainOtherPrivilege(Integer obtainOtherPrivilege) {
        this.obtainOtherPrivilege = obtainOtherPrivilege;
    }

    public Integer getUserInteractionRequired() {
        return userInteractionRequired;
    }

    public void setUserInteractionRequired(Integer userInteractionRequired) {
        this.userInteractionRequired = userInteractionRequired;
    }

    public Integer getRankingForHealth() {
        return rankingForHealth;
    }

    public void setRankingForHealth(Integer rankingForHealth) {
        this.rankingForHealth = rankingForHealth;
    }

    /**
     * Gets an unmodifiable list of software affected by this vulnerability.
     *
     * @return A list of vulnerable software.
     */
    public List<String> getVulnerableSoftware() {
        return Collections.unmodifiableList(vulnerableSoftware);
    }

    /**
     * Sets the list of vulnerable software, replacing any existing values.
     *
     * @param softwareList A list of affected software.
     */
    public void setVulnerableSoftware(List<String> softwareList) {
        this.vulnerableSoftware.clear();
        if (softwareList != null) {
            this.vulnerableSoftware.addAll(softwareList);
        }
    }

    public String getAttackVector() {
        return attackVector;
    }

    public void setAttackVector(String attackVector) {
        this.attackVector = attackVector;
    }

    public String getAccessComplexity() {
        return accessComplexity;
    }

    public void setAccessComplexity(String accessComplexity) {
        this.accessComplexity = accessComplexity;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public String getConfidentiality() {
        return confidentiality;
    }

    public void setConfidentiality(String confidentiality) {
        this.confidentiality = confidentiality;
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    public String getAvailability() {
        return availability;
    }

    public void setAvailability(String availability) {
        this.availability = availability;
    }

    /**
     * Returns the total count of vulnerable software associated with this vulnerability.
     *
     * @return The number of affected software products.
     */
    public int countVulnerableSoftware() {
        return vulnerableSoftware.size();
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * Generates a hash code based on the vulnerability ID.
     *
     * @return The hash code of this entry.
     */
    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    /**
     * Compares this entry with another object for equality.
     *
     * @param obj The object to compare against.
     * @return {@code true} if the objects are equal, otherwise {@code false}.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Entry entry = (Entry) obj;
        return Objects.equals(id, entry.id);
    }

    /**
     * Returns a string representation of this vulnerability entry.
     *
     * @return A string containing the vulnerability details.
     */
    @Override
    public String toString() {
        return "Entry{" +
                "id='" + id + '\'' +
                ", summary='" + summary + '\'' +
                ", score=" + score +
                ", attackVector='" + attackVector + '\'' +
                ", accessComplexity='" + accessComplexity + '\'' +
                ", authentication='" + authentication + '\'' +
                ", confidentiality='" + confidentiality + '\'' +
                ", integrity='" + integrity + '\'' +
                ", availability='" + availability + '\'' +
                ", severity='" + severity + '\'' +
                ", exploitability=" + exploitability +
                ", impact=" + impact +
                ", rankingForHealth=" + rankingForHealth +
                ", category='" + category + '\'' +
                ", vulnerableSoftware=" + vulnerableSoftware +
                '}';
    }
}
