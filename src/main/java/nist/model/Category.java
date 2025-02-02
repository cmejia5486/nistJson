package nist.model;

import java.util.List;

/**
 * Represents a <i>Category</i> in the NIST data feed.
 * A category groups vulnerabilities (CVEs) based on shared characteristics.
 * Each category contains multiple vulnerability entries and various metrics.
 * 
 * @author Carlos
 * @version 1.0
 */
public class Category {

    /**
     * The unique CVE ID of the category.
     */
    private String ID;

    /**
     * List of entries associated with this category.
     */
    private List<Entry> entries;

    /**
     * A brief summary describing the category.
     */
    private String summary;

    /**
     * The total number of vulnerabilities in this category.
     */
    private Integer number_of_vulnerabilities;

    /**
     * The average score of the vulnerabilities in this category.
     */
    private Double average_score;

    /**
     * The presence of the category across vulnerabilities.
     */
    private Double presence;

    /**
     * The impact value of the vulnerabilities in this category.
     */
    private Double impact;

    /**
     * The number of vulnerabilities classified as critical for health-related systems.
     */
    private Integer number_of_criticality_for_health_vulnerabilities;

    /**
     * Constructs a {@code Category} with the specified ID and summary.
     *
     * @param ID      The unique identifier for the category.
     * @param summary A brief description of the category.
     */
    public Category(String ID, String summary) {
        this.ID = ID;
        this.summary = summary;
    }

    /**
     * Default constructor for creating an empty {@code Category}.
     */
    public Category() {
    }

    /**
     * Gets the unique CVE ID of this category.
     *
     * @return The category ID.
     */
    public String getID() {
        return ID;
    }

    /**
     * Sets the unique CVE ID for this category.
     *
     * @param ID The new category ID.
     */
    public void setID(String ID) {
        this.ID = ID;
    }

    /**
     * Gets the list of entries associated with this category.
     *
     * @return A list of {@code Entry} objects.
     */
    public List<Entry> getEntries() {
        return entries;
    }

    /**
     * Sets the list of entries for this category.
     *
     * @param entries The new list of entries.
     */
    public void setEntries(List<Entry> entries) {
        this.entries = entries;
    }

    /**
     * Gets the summary of this category.
     *
     * @return The category summary.
     */
    public String getSummary() {
        return summary;
    }

    /**
     * Sets the summary for this category.
     *
     * @param summary The new category summary.
     */
    public void setSummary(String summary) {
        this.summary = summary;
    }

    /**
     * Gets the total number of vulnerabilities in this category.
     *
     * @return The number of vulnerabilities.
     */
    public Integer getNumber_of_vulnerabilities() {
        return number_of_vulnerabilities;
    }

    /**
     * Sets the total number of vulnerabilities in this category.
     *
     * @param number_of_vulnerabilities The new vulnerability count.
     */
    public void setNumber_of_vulnerabilities(Integer number_of_vulnerabilities) {
        this.number_of_vulnerabilities = number_of_vulnerabilities;
    }

    /**
     * Gets the average score of vulnerabilities in this category.
     *
     * @return The average score.
     */
    public Double getAverage_score() {
        return average_score;
    }

    /**
     * Sets the average score for vulnerabilities in this category.
     *
     * @param average_score The new average score.
     */
    public void setAverage_score(Double average_score) {
        this.average_score = average_score;
    }

    /**
     * Gets the presence value of this category.
     *
     * @return The presence value.
     */
    public Double getPresence() {
        return presence;
    }

    /**
     * Sets the presence value for this category.
     *
     * @param presence The new presence value.
     */
    public void setPresence(Double presence) {
        this.presence = presence;
    }

    /**
     * Gets the impact value of vulnerabilities in this category.
     *
     * @return The impact value.
     */
    public Double getImpact() {
        return impact;
    }

    /**
     * Sets the impact value for this category.
     *
     * @param impact The new impact value.
     */
    public void setImpact(Double impact) {
        this.impact = impact;
    }

    /**
     * Gets the number of vulnerabilities classified as critical for health-related systems.
     *
     * @return The number of health-related critical vulnerabilities.
     */
    public Integer getNumber_of_criticality_for_health_vulnerabilities() {
        return number_of_criticality_for_health_vulnerabilities;
    }

    /**
     * Sets the number of vulnerabilities classified as critical for health-related systems.
     *
     * @param number_of_criticality_for_health_vulnerabilities The new count of health-critical vulnerabilities.
     */
    public void setNumber_of_criticality_for_health_vulnerabilities(Integer number_of_criticality_for_health_vulnerabilities) {
        this.number_of_criticality_for_health_vulnerabilities = number_of_criticality_for_health_vulnerabilities;
    }

    /**
     * Gets the total number of vulnerability entries in this category.
     *
     * @return The total number of entries.
     */
    public int getTotalEntries() {
        return entries != null ? entries.size() : 0;
    }

    /**
     * Generates a hash code based on the category ID.
     *
     * @return The hash code of the category.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((ID == null) ? 0 : ID.hashCode());
        return result;
    }

    /**
     * Compares this category to another object for equality.
     *
     * @param obj The object to compare against.
     * @return {@code true} if the objects are equal, otherwise {@code false}.
     */
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

    /**
     * Returns a string representation of this category.
     *
     * @return A string containing the category details.
     */
    @Override
    public String toString() {
        return "Category{" +
                "ID=" + ID +
                ", entries=" + entries +
                ", summary=" + summary +
                ", number_of_vulnerabilities=" + number_of_vulnerabilities +
                ", average_score=" + average_score +
                ", presence=" + presence +
                ", impact=" + impact +
                ", number_of_criticality_for_health_vulnerabilities=" + number_of_criticality_for_health_vulnerabilities +
                '}';
    }
}
