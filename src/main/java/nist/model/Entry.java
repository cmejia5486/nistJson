package nist.model;

import java.util.ArrayList;

/**
 * Represents a <i>Entry</i> for a vulnerability in NIST data feed
 *
 * @author mario
 *
 */
public class Entry {

    /**
     * ID of the vulnerability
     */
    private String ID;
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
    private ArrayList<String> vulnerableSoftware;

    public Entry() {

    }

    public Entry(String id, Integer ranking) {
        this.ID = id;
        this.rankingForHealth = ranking;
    }

    public String getID() {
        return ID;
    }

    public void setID(String iD) {
        ID = iD;
    }

    public boolean hasCategory() {
        return category != null;
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

    public ArrayList<String> getVulnerableSoftware() {
        return vulnerableSoftware;
    }

    public void setVulnerableSoftware(ArrayList<String> vulnerableSoftware) {
        this.vulnerableSoftware = vulnerableSoftware;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((ID == null) ? 0 : ID.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        Entry other = (Entry) obj;
        if (ID == null) {
            if (other.ID != null) {
                return false;
            }
        } else if (!ID.equals(other.ID)) {
            return false;
        }
        return true;
    }

    public String getAttackVector() {
        return attackVector;
    }

    public void setAttackVector(String accessVector) {
        this.attackVector = accessVector;
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
    public String toString() {
        return "Entry{" + "ID=" + ID + ", summary=" + summary + ", score=" + score + ", accessVector=" + attackVector + ", accessComplexity=" + accessComplexity + ", authentication=" + authentication + ", confidentiality=" + confidentiality + ", integrity=" + integrity + ", availability=" + availability + ", severity=" + severity + ", exploitability=" + exploitability + ", impact=" + impact + ", obtainAllPrivilege=" + obtainAllPrivilege + ", obtainUserPrivilege=" + obtainUserPrivilege + ", obtainOtherPrivilege=" + obtainOtherPrivilege + ", userInteractionRequired=" + userInteractionRequired + ", rankingForHealth=" + rankingForHealth + ", category=" + category + ", vulnerableSoftware=" + vulnerableSoftware + '}';
    }

}
