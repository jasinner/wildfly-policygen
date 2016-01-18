#!/usr/bin/groovy
package com.redhat.prodsec.jboss
import java.util.regex.*
import com.redhat.prodsec.jboss.Permission

class LogParser{

    private static Pattern p = ~/(?i)permission\s"\("(?<clazz>[^"]*+)"\s"(?<permission>[^"]*+)"(?:\s"(?<action>[^"]*+)")?\)[\sa-z:\/\("-]*modules\/system\/layers\/base\/(?<module>[a-z\/]*)main/
    private Matcher m = null

    LogParser(){
        testRegex('(permission "("java.lang.RuntimePermission" "setClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/')
        testRegex('2016-01-12 12:38:47,439 DEBUG [org.wildfly.security.access] (Controller Boot Thread) Permission check failed (permission "("java.lang.RuntimePermission" "getClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "ModuleClassLoader for Module "org.jboss.as.controller:main" from local module loader @47089e5f (finder: local module finder @4141d797 (roots: /home/jshepher/apps/product-distributions/modules,/home/jshepher/apps/product-distributions/modules/system/layers/base))")')
        testRegex('2016-01-12 12:38:46,566 DEBUG [org.wildfly.security.access] (Periodic Recovery) Permission check failed (permission "("java.io.FilePermission" "/home/jshepher/apps/product-distributions/standalone/data/tx-object-store/ShadowNoFileLockStore/defaultStore" "read")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/transactions/main/wildfly-transactions-10.0.0.CR6-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('2016-01-12 12:38:55,427 DEBUG [org.wildfly.security.access] (MSC service thread 1-7) Permission check failed (permission "("org.jboss.as.controller.security.ControllerPermission" "createCaller")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/jmx/main/wildfly-jmx-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
    }

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
                new Permission(module: m.group('module'),
                    clazz: m.group('clazz'),
                    permission: m.group('permission'),
                    action: m.group('action')
                )
            )
        }
    }

    def Matcher resetMatcher(String subject){
        if(m != null)
            m.reset(subject)
        else
            m = p.matcher(subject);
    }

    static void main(String[] args) {
        LogParser lp = new LogParser();
        Set results = lp.parseFile('testData/secmgr.log')
        println "saved permissions: " + results.size()
    }

    def testRegex(String testString){
        resetMatcher(testString)
        String[] groupList = ['clazz', 'permission', 'action', 'module']
        while(m.find()){
            groupList.each{
                if(it != 'action')
                    assert m.group(it) != null
            }
        }
    }
}