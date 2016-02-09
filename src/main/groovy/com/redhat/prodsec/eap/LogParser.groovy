package com.redhat.prodsec.eap
import java.util.regex.*
import com.redhat.prodsec.eap.ModulePermission

class LogParser{
    //https://regex101.com/r/dT1bV4/3
    //This regex using negative lookahead to avoid terminating matches in name group that contain a '"' character
    //http://stackoverflow.com/questions/406230/regular-expression-to-match-line-that-doesnt-contain-a-word
    private static Pattern p = ~/(?i)permission\s"\("(?<clazz>[^"]*+)"\s"(?<name>((?!"\s).)+)"(?:\s"(?<action>[^"]*+)")?\)[\sa-zA-Z:\/\("-]*modules\/system\/layers\/base\/(?<module>[a-z\/]*)\/main/
    private Matcher m = null


    def Set parseFile(String fileName){
        Set results = new HashSet()
        new File(fileName).eachLine {
            line -> parseLine(line, results)
        }
        return results;
    }

    def void parseLine(String line, Set results){
        resetMatcher(line)
        while(m.find()){
            results.add(
                new ModulePermission(m.group('module'),
                    m.group('clazz'),
                    m.group('name'),
                    m.group('action')
                )
            )
        }
    }

    private void resetMatcher(String subject){
        if(m != null)
            m.reset(subject)
        else
            m = p.matcher(subject);
    }


}
