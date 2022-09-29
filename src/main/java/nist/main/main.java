/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.main;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import nist.Functions.JsonProcessor;
import nist.Utility.Functions;

/**
 *
 * @author Carlos
 */
public class main {

    public static void main(String[] args) {
        try {
            List<String> keys = new ArrayList<String>();
            //fill keywords for searching
            keys.add("HEALTH");
            keys.add("MEDIC");
            for (int i = 2002; i < 2022; i++) {

                //load  json file
                JsonObject jsonObject = new JsonParser().parse(new FileReader("JsonData/nvdcve-1.1-" + i + ".json")).getAsJsonObject();
                //create a json processor for having data
                JsonProcessor jsonProcessor = new JsonProcessor(jsonObject, keys);
                //export data to csv format
                jsonProcessor.cveToCSV("results/" + i + "-cve.csv", true);
                jsonProcessor.cweToCSV("results/" + i + "-cwe.csv", true);
            }
            JsonObject jsonObject = new JsonParser().parse(new FileReader(Functions.FILETOTAL)).getAsJsonObject();
            //create a json processor for having data
            JsonProcessor jsonProcessor = new JsonProcessor(jsonObject, keys);
            //export data to csv format
            jsonProcessor.cveToCSV("results/Total-cve.csv", true);
            jsonProcessor.cweToCSV("results/Total-cwe.csv", true);
        } catch (Exception e) {
            System.out.println("error: " + e);
        }

    }
}
