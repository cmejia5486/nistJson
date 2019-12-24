/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package main;

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
            //load  json file
            JsonObject jsonObject = new JsonParser().parse(new FileReader(Functions.FILE2002)).getAsJsonObject();
            //create a json processor for having data
            JsonProcessor jsonProcessor = new JsonProcessor(jsonObject, keys);
            //export data to csv format
            jsonProcessor.cveToCSV("results/2002-cve.csv", true);
            jsonProcessor.cweToCSV("results/2002-cwe.csv", true);

        } catch (Exception e) {
            System.out.println("error: " + e);
        }

    }
}
