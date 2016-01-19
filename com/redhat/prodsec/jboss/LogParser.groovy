#!/usr/bin/groovy
package com.redhat.prodsec.jboss
import java.util.regex.*
import com.redhat.prodsec.jboss.Permission

class LogParser{

    private static Pattern p = ~/(?i)permission\s"\("(?<clazz>[^"]*+)"\s"(?<name>[^"]*+)"(?:\s"(?<action>[^"]*+)")?\)[\sa-z:\/\("-]*modules\/system\/layers\/base\/(?<module>[a-z\/]*)\/main/
    private Matcher m = null

    static{
        testRegex('(permission "("java.lang.RuntimePermission" "setClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/')
        testRegex('2016-01-12 12:38:47,439 DEBUG [org.wildfly.security.access] (Controller Boot Thread) Permission check failed (permission "("java.lang.RuntimePermission" "getClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "ModuleClassLoader for Module "org.jboss.as.controller:main" from local module loader @47089e5f (finder: local module finder @4141d797 (roots: /home/jshepher/apps/product-distributions/modules,/home/jshepher/apps/product-distributions/modules/system/layers/base))")')
        testRegex('2016-01-12 12:38:46,566 DEBUG [org.wildfly.security.access] (Periodic Recovery) Permission check failed (permission "("java.io.FilePermission" "/home/jshepher/apps/product-distributions/standalone/data/tx-object-store/ShadowNoFileLockStore/defaultStore" "read")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/transactions/main/wildfly-transactions-10.0.0.CR6-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('2016-01-12 12:38:55,427 DEBUG [org.wildfly.security.access] (MSC service thread 1-7) Permission check failed (permission "("org.jboss.as.controller.security.ControllerPermission" "createCaller")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/jmx/main/wildfly-jmx-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('2016-01-12 12:38:47,008 DEBUG [org.wildfly.security.access] (MSC service thread 1-6) Permission check failed (permission "("javax.management.MBeanPermission" "org.xnio.nio.NioXnioWorker$1#-[org.xnio:provider="nio",type=Xnio,worker="XNIO-1"]" "registerMBean")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/domain-http-interface/main/wildfly-domain-http-interface-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
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
                    name: m.group('name'),
                    action: m.group('action')
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

    private static testRegex(String testString){
        LogParser parser = new LogParser()
        parser.resetMatcher(testString)
        String[] groupList = ['clazz', 'name', 'action', 'module']
        while(parser.m.find()){
            groupList.each{
                if(it != 'action')
                    assert parser.m.group(it) != null
            }
        }
    }
}
