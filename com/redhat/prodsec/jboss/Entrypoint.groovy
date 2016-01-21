package com.redhat.prodsec.jboss

import com.redhat.prodsec.*

class EntryPoint{


    static void main(String[] args) {
        if(args.length < 1){
            println("Usage 'groovy com/redhat/prodsec/jboss/Entrypoint.groovy <logpath>'")
            System.exit(1)
        }
        def results = parseLog(args[0])
        writeToModules(buildPermissionsMap(results))
    }

    static private writeToModules(Map moduleDefinitions){
        def modUtil = new ModuleUtil()
        moduleDefinitions.keySet().each{ module->
            XmlPrinter.printNode(moduleDefinitions.get(module), modUtil.getModuleFile(module))
        }
    }

    static private buildPermissionsMap(Set results){
        def g = new Grouper(results)
        Map moduleDefinitions = new HashMap(g.permissionsByModule.keySet().size())
        g.permissionsByModule.keySet().each{ module->
            Node document = combineExistingModule(module, g.permissionsByModule)
            moduleDefinitions.put(module, document)
        }
        return moduleDefinitions;
    }

    static private combineExistingModule(String module, Map permissionsMap){
        def modUtil = new ModuleUtil()
        Node root = modUtil.readExistingModule(module)
        Set permissions = permissionsMap.get(module)
        if(modUtil.hasPermissions(root)){
            def existingPerms = modUtil.buildPermissions(root)
            permissions.addAll(existingPerms)
        }
        return modUtil.updatePerms(module, permissions)
    }

    static private Set parseLog(String logFile){
        assert new File(logFile).isFile()
        def lp = new LogParser();
        Set results = lp.parseFile(logFile)
        println "saved permissions: " + results.size()
        return results;
    }
}
