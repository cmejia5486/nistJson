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
