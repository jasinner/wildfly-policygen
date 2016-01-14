#!/usr/bin/groovy
import java.util.regex.*

class Input{

    private Pattern p = ~/(?i)permission\s"\("([^"]*+)"\s"([^"]*+)"\)"[\sa-z:\/\("-]*modules\/system\/layers\/base\/([a-z\/]*)main/

    static{
        testRegex('("java.lang.RuntimePermission" "setClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/')
        testRegex('2016-01-12 12:38:47,439 DEBUG [org.wildfly.security.access] (Controller Boot Thread) Permission check failed (permission "("java.lang.RuntimePermission" "getClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "ModuleClassLoader for Module "org.jboss.as.controller:main" from local module loader @47089e5f (finder: local module finder @4141d797 (roots: /home/jshepher/apps/product-distributions/modules,/home/jshepher/apps/product-distributions/modules/system/layers/base))")')
    }

    def parseFile(String fileName){
       new File(fileName).eachLine { line ->
           m = p.matcher(line)
           count = m.groupCount()
       }
   }

    def testRegex(String testString){
        Matcher test1 = p.matcher(testString)
        assert test1.hasGroup()
        assert test1.groupCount() == 3
    }
}