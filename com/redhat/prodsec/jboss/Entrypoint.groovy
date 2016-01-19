package com.redhat.prodsec.jboss

import com.redhat.prodsec.*

class EntryPoint{


    static void main(String[] args) {
        if(args.length < 1){
            println("Usage 'groovy com/redhat/prodsec/jboss/Entrypoint.groovy <logpath>'")
            System.exit(1)
        }
        def results = parseLog(args[0])
        createGrouper(results)
    }

    static private createGrouper(Set results){
        def g = new Grouper(results)
        def xmlMan = new XmlManipulator()
        g.permissionsByModule.keySet().each{
            Node root = xmlMan.readExistingModule(it)
            if(xmlMan.hasPermissions(root)){
                def existingPerms = xmlMan.buildPermissions(root)
                g.permissionsByModule.get(it).addAll(existingPerms)
            }
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
