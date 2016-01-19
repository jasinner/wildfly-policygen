package com.redhat.prodsec.jboss

import com.redhat.prodsec.*

class EntryPoint{


    static void main(String[] args) {
        if(args.length < 1){
            println("Usage 'groovy com/redhat/prodsec/jboss/Entrypoint.groovy <logpath>'")
            System.exit(1)
        }
        def results = parseLog(args[0])
        def g = new Grouper(results)
        def xmlMan = new XmlManipulator()
        g.permissionByModule.keySet().each{
            Node root = xmlMan.readExistingModule(it)
            println "$it has permisions " + xmlMan.hasPermissions(root)
        }
    }

    static private Set parseLog(String logFile){
        assert new File(logFile).isFile()
        def lp = new LogParser();
        Set results = lp.parseFile(logFile)
        println "saved permissions: " + results.size()
        return results;
    }
}
