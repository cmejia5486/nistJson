package nist.model;

import java.util.List;

/**
 * Represents a <i>Category</i> for a category in NIST data feed
 *
 * @author mario
 *
 */
public class Category {

    /**
     * CVE ID of the category
     */
    private String ID;

    /**
     * Entries that have this category
     */
    private List<Entry> entries;

    private String summary;
    private Integer number_of_vulnerabilities;
    private Double average_score;
    private Double presence;
    private Double impact;

    public Category(String ID, String summary) {
        this.ID = ID;
        this.summary = summary;
    }

    public Category() {
    }

    public String getID() {
        return ID;
    }

    public void setID(String ID) {
        this.ID = ID;
    }

    public List<Entry> getEntries() {
        return entries;
    }

    public void setEntries(List<Entry> entries) {
        this.entries = entries;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public Integer getNumber_of_vulnerabilities() {
        return number_of_vulnerabilities;
    }

    public void setNumber_of_vulnerabilities(Integer number_of_vulnerabilities) {
        this.number_of_vulnerabilities = number_of_vulnerabilities;
    }

    public Double getAverage_score() {
        return average_score;
    }

    public void setAverage_score(Double average_score) {
        this.average_score = average_score;
    }

    public Double getPresence() {
        return presence;
    }

    public void setPresence(Double presence) {
        this.presence = presence;
    }

    public Double getImpact() {
        return impact;
    }

    public void setImpact(Double impact) {
        this.impact = impact;
    }

    /**
     * Gets the total number of vulnerability entries of the category
     *
     * @return total number of entries
     */
    public int getTotalEntries() {
        return entries.size();
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
        Category other = (Category) obj;
        if (ID == null) {
            if (other.ID != null) {
                return false;
            }
        } else if (!ID.equals(other.ID)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        //return "Category{" + "ID=" + ID + ", entries=" + entries + ", summary=" + summary + ", number_of_vulnerabilities=" + number_of_vulnerabilities + ", average_score=" + average_score + ", presence=" + presence + ", impact=" + impact + '}';
        return "Category{" + "ID=" + ID + ", summary=" + summary + ", number_of_vulnerabilities=" + number_of_vulnerabilities + ", average_score=" + average_score + ", presence=" + presence + ", impact=" + impact + '}';
    }

}
