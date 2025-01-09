package nist.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents an <i>Entry</i> for a vulnerability in NIST data feed.
 *
 * @author Carlos
 */
public class Entry {

    private String id;
    private String summary;
    private double score;
    private String attackVector;
    private String accessComplexity;
    private String authentication;
    private String confidentiality;
    private String integrity;
    private String availability;
    private String severity;
    private double exploitability;
    private double impact;
    private Integer obtainAllPrivilege;
    private Integer obtainUserPrivilege;
    private Integer obtainOtherPrivilege;
    private Integer userInteractionRequired;
    private Integer rankingForHealth;

    private String category;
    private final List<String> vulnerableSoftware;

    public Entry() {
        this.vulnerableSoftware = new CopyOnWriteArrayList<>();
    }

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

    public List<String> getVulnerableSoftware() {
        return Collections.unmodifiableList(vulnerableSoftware);
    }

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

    public int countVulnerableSoftware() {
        return vulnerableSoftware.size();
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Entry entry = (Entry) obj;
        return Objects.equals(id, entry.id);
    }

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
                ", obtainAllPrivilege=" + obtainAllPrivilege +
                ", obtainUserPrivilege=" + obtainUserPrivilege +
                ", obtainOtherPrivilege=" + obtainOtherPrivilege +
                ", userInteractionRequired=" + userInteractionRequired +
                ", rankingForHealth=" + rankingForHealth +
                ", category='" + category + '\'' +
                ", vulnerableSoftware=" + vulnerableSoftware +
                '}';
    }
}
