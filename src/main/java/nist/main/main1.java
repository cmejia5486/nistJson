/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nist.main;

import java.io.*;
import java.nio.charset.Charset;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author Carlos
 */
public class main1 {

    static Integer anioInicio = 2002;
    static Integer anioFin = 2021;

    public static void main(String[] args) {
        try {

            //obtiene las cwe y CVE
            List<String> cweList = getCWE();

            //recorro los CWE
            for (String cweElement : cweList) {
                impactFromCwe(cweElement, anioInicio, anioFin, true);
                presenciaFromCwe(cweElement, anioInicio, anioFin, true);
            }

            totalImpactFromCweList(cweList, anioInicio, anioFin, true);
            totalPresenciaFromCweList(cweList, anioInicio, anioFin, true);
            totalImpactAverageFromCwe(cweList, true);
            totalPresenciaAverageFromCwe(cweList, true);

            impactFromCve(anioInicio, anioFin, true);
            presenceFromCve(anioInicio, anioFin, true);
            criticalityFromCve(anioInicio, anioFin, true);
            exploitabilityFromCve(anioInicio, anioFin, true);
            accessComplexityFromCve(anioInicio, anioFin, true);
            authenticationFromCve(anioInicio, anioFin, true);
            confidentialityFromCve(anioInicio, anioFin, true);
            integrityFromCve(anioInicio, anioFin, true);
            availabilityFromCve(anioInicio, anioFin, true);

            averageimpactFromCve(anioInicio, anioFin, true);
            averagepresenceFromCve(anioInicio, anioFin, true);
            summaryCriticalityforHealthFromCve(anioInicio, anioFin, true);
            averageExploitabilityFromCve(anioInicio, anioFin, true);

            //finrecorro los CWE
        } catch (Exception e) {
            System.out.println("error: " + e);
        }

    }

    public static List<String> getCWE() {
        List<String> cwe = new ArrayList<>();
        try {

            BufferedReader reader = new BufferedReader(new FileReader("results/Total-cwe.csv"));
            String line = null;
            Integer i = 0;
            while ((line = reader.readLine()) != null) {
                i = i + 1;
                if (i > 1) {
                    String[] parts = line.split(";");
                    if (parts.length > 3) {
                        cwe.add(parts[0]);
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("error al obtener las CWE del fichero total: " + e);
        }
        return cwe;
    }

    public static void impactFromCwe(String cwe, Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String ficheroCwe;
        String nombreFicheroExcel = "../../spss/1. impacto cwe por año/" + cwe + "-impacto.csv";
        String valorAnual = "0";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; impacto\n");
            for (int anio = ai; anio < af + 1; anio++) {
                valorAnual = "0";
                ficheroCwe = anio + "-cwe.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCwe));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            if (cwe.equals(parts[0])) {
                                valorAnual = parts[5];
                                break;
                            }
                        }
                    }
                }
                sb.append(anio + ";" + valorAnual + "\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en impactFromCwe fue: " + e);
        }

    }

    public static void totalImpactFromCweList(List<String> cweList, Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String ficheroCwe;
        String nombreFicheroExcel = "../../spss/1. impacto cwe por año/totalCWE-impacto.csv";
        String valorAnual = "0";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("cwe; impacto\n");
            Collections.sort(cweList);
            for (String cwe : cweList) {
                for (int anio = ai; anio < af + 1; anio++) {
                    valorAnual = "0";
                    ficheroCwe = anio + "-cwe.csv";
                    BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCwe));
                    String line = null;
                    Integer i = 0;
                    while ((line = reader.readLine()) != null) {
                        i = i + 1;
                        if (i > 1) {
                            String[] parts = line.split(";");
                            if (parts.length > 3) {
                                if (cwe.equals(parts[0])) {
                                    valorAnual = parts[5];
                                    break;
                                }
                            }
                        }
                    }
                    sb.append(cwe).append(";").append(valorAnual).append("\n");
                }
            }

            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en totalImpactFromCweList fue: " + e);
        }

    }

    public static void totalPresenciaFromCweList(List<String> cweList, Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String ficheroCwe;
        String nombreFicheroExcel = "../../spss/2. presencia cwe por año/totalCWE-presencia.csv";
        String valorAnual = "0";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("cwe; presencia\n");
            Collections.sort(cweList);
            for (String cwe : cweList) {
                for (int anio = ai; anio < af + 1; anio++) {
                    valorAnual = "0";
                    ficheroCwe = anio + "-cwe.csv";
                    BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCwe));
                    String line = null;
                    Integer i = 0;
                    while ((line = reader.readLine()) != null) {
                        i = i + 1;
                        if (i > 1) {
                            String[] parts = line.split(";");
                            if (parts.length > 3) {
                                if (cwe.equals(parts[0])) {
                                    valorAnual = parts[4];
                                    break;
                                }
                            }
                        }
                    }
                    sb.append(cwe).append(";").append(valorAnual).append("\n");
                }
            }

            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en totalPresenciaFromCweList fue: " + e);
        }

    }

    public static void impactFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/3. impacto cve por año/CVE-impacto.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; impacto\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[11]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en impactFromCve fue: " + e);
        }

    }

    public static void averageimpactFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Integer ai = anioInicio;
        Integer af = anioFin;
        Double promedio = 0D;
        String nombreFicheroExcel = "../../spss/3. impacto cve por año/averageCVE-impacto.csv";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; impacto\n");
            for (int anio = ai; anio < af + 1; anio++) {
                promedio = 0D;
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/3. impacto cve por año/CVE-impacto.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(anio + "")) {
                            i = i + 1;
                            promedio = promedio + Double.parseDouble(parts[1].replace(",", "."));
                        }
                    }
                }
                promedio = promedio / i;
                sb.append(anio).append(";").append(df.format(promedio).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en impactFromCve fue: " + e);
        }

    }

    public static void totalImpactAverageFromCwe(List<String> cweList, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Double promedio = 0D;
        String nombreFicheroExcel = "../../spss/1. impacto cwe por año/totalAverageCWE-impacto.csv";
        StringBuilder sb;
        try {
            Collections.sort(cweList);
            sb = new StringBuilder();
            sb.append("cwe; impacto\n");
            for (String cwe : cweList) {
                promedio = 0D;
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/1. impacto cwe por año/totalCWE-impacto.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(cwe + "")) {
                            i = i + 1;
                            promedio = promedio + Double.parseDouble(parts[1].replace(",", "."));
                        }
                    }
                }
                promedio = promedio / i;
                sb.append(cwe).append(";").append(df.format(promedio).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en totalImpactAverageFromCwe fue: " + e);
        }

    }

    public static void totalPresenciaAverageFromCwe(List<String> cweList, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Double promedio = 0D;
        String nombreFicheroExcel = "../../spss/2. presencia cwe por año/totalAverageCWE-presencia.csv";
        StringBuilder sb;
        try {
            Collections.sort(cweList);
            sb = new StringBuilder();
            sb.append("cwe; presencia\n");
            for (String cwe : cweList) {
                promedio = 0D;
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/2. presencia cwe por año/totalCWE-presencia.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(cwe + "")) {
                            i = i + 1;
                            promedio = promedio + Double.parseDouble(parts[1].replace(",", "."));
                        }
                    }
                }
                promedio = promedio / i;
                sb.append(cwe).append(";").append(df.format(promedio).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en totalPresenciaAverageFromCwe fue: " + e);
        }

    }

    public static void averagepresenceFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Integer ai = anioInicio;
        Integer af = anioFin;
        Double promedio = 0D;
        String nombreFicheroExcel = "../../spss/4. presencia cve por año/averageCVE-presencia.csv";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; presencia\n");
            for (int anio = ai; anio < af + 1; anio++) {
                promedio = 0D;
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/4. presencia cve por año/CVE-presencia.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(anio + "")) {
                            i = i + 1;
                            promedio = promedio + Double.parseDouble(parts[1].replace(",", "."));
                        }
                    }
                }
                promedio = promedio / i;
                sb.append(anio).append(";").append(df.format(promedio).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en impactFromCve fue: " + e);
        }

    }

    public static void summaryCriticalityforHealthFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/5. Criticality cve por año/CVE-SummaryCriticality.csv";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; criticalityNumber\n");
            for (int anio = ai; anio < af + 1; anio++) {
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/5. Criticality cve por año/CVE-Criticality.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(anio + "") &&parts[1].equals("1") ) {
                            i = i + 1;
                        }
                    }
                }
                sb.append(anio).append(";").append(df.format(i).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en averageCriticalityforHealthFromCve fue: " + e);
        }

    }

    public static void averageExploitabilityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        DecimalFormat df = new DecimalFormat("#.000");
        Integer ai = anioInicio;
        Integer af = anioFin;
        Double promedio = 0D;
        String nombreFicheroExcel = "../../spss/6. Exploitability cve por año/CVE-AverageExploitability.csv";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; exploitability\n");
            for (int anio = ai; anio < af + 1; anio++) {
                promedio = 0D;
                BufferedReader reader = new BufferedReader(new FileReader("../../spss/6. Exploitability cve por año/CVE-Exploitability.csv"));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(";");
                    if (parts.length > 0) {
                        if (parts[0].equals(anio + "")) {
                            i = i + 1;
                            promedio = promedio + Double.parseDouble(parts[1].replace(",", "."));
                        }
                    }
                }

                promedio = promedio / i;
                sb.append(anio).append(";").append(df.format(promedio).replace(".", ",")).append("\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en averageCriticalityforHealthFromCve fue: " + e);
        }

    }

    public static void presenceFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/4. presencia cve por año/CVE-presencia.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; presencia\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[10]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en impactFromCve fue: " + e);
        }
    }

    public static void criticalityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/5. Criticality cve por año/CVE-Criticality.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; criticality\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[12]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en criticalityFromCve fue: " + e);
        }

    }

    public static void exploitabilityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/6. Exploitability cve por año/CVE-Exploitability.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; exploitability\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[7]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en criticalityFromCve fue: " + e);
        }

    }

    public static void accessComplexityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/7. Access Complexity cve por año/CVE-Access Complexity.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; accessComplexity\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[2]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en accessComplexityFromCve fue: " + e);
        }

    }

    public static void authenticationFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/8. Authentication cve por año/CVE-Authentication.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; authentication\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[3]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en accessComplexityFromCve fue: " + e);
        }

    }

    public static void confidentialityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/9. Confidentiality cve por año/CVE-Confidentiality.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; confidentiality\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[4]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en accessComplexityFromCve fue: " + e);
        }

    }

    public static void integrityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/10. Integrity cve por año/CVE-Integrity.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; integrity\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[5]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en accessComplexityFromCve fue: " + e);
        }

    }

    public static void availabilityFromCve(Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String nombreFicheroExcel = "../../spss/11. Avalilability cve por año/CVE-availability.csv";
        StringBuilder sb;
        String ficheroCve;
        try {
            sb = new StringBuilder();
            sb.append("anio; availability\n");
            for (int anio = ai; anio < af + 1; anio++) {
                ficheroCve = anio + "-cve.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCve));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            sb.append(anio).append(";").append(parts[6]).append("\n");
                        }
                    }
                }

            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en accessComplexityFromCve fue: " + e);
        }

    }

    public static void presenciaFromCwe(String cwe, Integer anioInicio, Integer anioFin, boolean removeFileIfExists) {
        Integer ai = anioInicio;
        Integer af = anioFin;
        String ficheroCwe;
        String nombreFicheroExcel = "../../spss/2. presencia cwe por año/" + cwe + "-presencia.csv";
        String valorAnual = "0";
        StringBuilder sb;
        try {
            sb = new StringBuilder();
            sb.append("anio; presencia\n");
            for (int anio = ai; anio < af + 1; anio++) {
                valorAnual = "0";
                ficheroCwe = anio + "-cwe.csv";
                BufferedReader reader = new BufferedReader(new FileReader("results/" + ficheroCwe));
                String line = null;
                Integer i = 0;
                while ((line = reader.readLine()) != null) {
                    i = i + 1;
                    if (i > 1) {
                        String[] parts = line.split(";");
                        if (parts.length > 3) {
                            if (cwe.equals(parts[0])) {
                                valorAnual = parts[4];
                                break;
                            }
                        }
                    }
                }
                sb.append(anio + ";" + valorAnual + "\n");
            }
            String content = sb.toString();
            File file = new File(nombreFicheroExcel);
            if (removeFileIfExists
                    && file.exists()) {
                file.delete();
            }

            file.createNewFile();

            FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
        } catch (Exception e) {
            System.out.println("el error en presenceFromCwe fue: " + e);
        }

    }

}
