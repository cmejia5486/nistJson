/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.Utility;

import java.text.DecimalFormat;

/**
 * Utility class providing commonly used functions and constants for file paths.
 * This class includes helper methods for string validation and numeric formatting.
 * 
 * @author Carlos
 * @version 1.0
 */
public class Functions {

    /** Path to JSON files containing CVE data for each year. */
    public static final String FILE2002 = "JsonData/nvdcve-1.1-2002.json";
    public static final String FILE2003 = "JsonData/nvdcve-1.1-2003.json";
    public static final String FILE2004 = "JsonData/nvdcve-1.1-2004.json";
    public static final String FILE2005 = "JsonData/nvdcve-1.1-2005.json";
    public static final String FILE2006 = "JsonData/nvdcve-1.1-2006.json";
    public static final String FILE2007 = "JsonData/nvdcve-1.1-2007.json";
    public static final String FILE2008 = "JsonData/nvdcve-1.1-2008.json";
    public static final String FILE2009 = "JsonData/nvdcve-1.1-2009.json";
    public static final String FILE2010 = "JsonData/nvdcve-1.1-2010.json";
    public static final String FILE2011 = "JsonData/nvdcve-1.1-2011.json";
    public static final String FILE2012 = "JsonData/nvdcve-1.1-2012.json";
    public static final String FILE2013 = "JsonData/nvdcve-1.1-2013.json";
    public static final String FILE2014 = "JsonData/nvdcve-1.1-2014.json";
    public static final String FILE2015 = "JsonData/nvdcve-1.1-2015.json";
    public static final String FILE2016 = "JsonData/nvdcve-1.1-2016.json";
    public static final String FILE2017 = "JsonData/nvdcve-1.1-2017.json";
    public static final String FILE2018 = "JsonData/nvdcve-1.1-2018.json";
    public static final String FILE2019 = "JsonData/nvdcve-1.1-2019.json";
    public static final String FILE2020 = "JsonData/nvdcve-1.1-2020.json";
    public static final String FILE2021 = "JsonData/nvdcve-1.1-2021.json";
    public static final String FILE2022 = "JsonData/nvdcve-1.1-2022.json";
    public static final String FILE2023 = "JsonData/nvdcve-1.1-2023.json";
    public static final String FILE2024 = "JsonData/nvdcve-1.1-2024.json";
    public static final String FILE2025 = "JsonData/nvdcve-1.1-2025.json";

    /** Path to the consolidated JSON file containing total CVE data. */
    public static final String FILETOTAL = "JsonData/Total.json";

    /**
     * Checks if a given string is null and returns an empty string instead.
     *
     * @param value The string to be checked.
     * @return The original string if not null; otherwise, an empty string.
     */
    public static String CheckString(String value) {
        String response = "";
        if (value != null) {
            response = value;
        }
        return response;
    }

    /**
     * Formats a given double value to four decimal places.
     * Returns 0.00 if the value is less than or equal to 0.
     *
     * @param value The double value to format.
     * @return The formatted double value rounded to four decimal places.
     */
    public static Double fourDecimalsDouble(Double value) {
        Double response = 0.00D;
        DecimalFormat df = new DecimalFormat("#.0000");
        if (value > 0D) {
            response = Double.parseDouble(df.format(value).replace(",", "."));
        }
        return response;
    }
}
