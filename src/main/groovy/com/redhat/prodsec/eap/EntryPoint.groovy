package com.redhat.prodsec.eap

import java.security.Permission

import groovy.util.logging.Log

@Log
class EntryPoint {

    static enum Modes {
        MODULES, DEPLOYMENT
    }

    static void main(String[] args) {
        if (args.length < 1) {
            println("Usage 'groovy com/redhat/prodsec/jboss/Entrypoint.groovy logpath <mode>'")
            System.exit(1)
        }
        def mode = checkMode(args)
        Map<String, Set<Permission>> results = parseLog(args[0], mode)
        if (mode == Modes.MODULES)
            updateModules(results)
        else {
            generatePermissions(results)
        }
    }

    static void generatePermissions(Map<String, Set<Permission>> stringSetMap) {
        stringSetMap.each {
            k, v ->
                def writer = new FileWriter(k + ".permissions.xml")
                DeploymentUtil.createPermissions(v, writer)
                writer.flush()
        }
    }


    private static void updateModules(Map<String, Set<Permission>> results) {
        def moduleToUpdate = results.keySet()
        moduleToUpdate.each { module ->
            Node moduleNode;
            Set<Permission> permissionsToAdd = results.get(module)
            log.info("Trying to build permission for ${module}")
            Set<Permission> existingPerms = ModuleUtil.buildPermissions(module)
            if (existingPerms == null) {
                log.info("Found no existing permissions in ${module}," +
                        "adding ${permissionsToAdd.size()} now")
                moduleNode = ModuleUtil.addPerms(module, permissionsToAdd)
            } else {
                log.info("Found ${existingPerms.size()} existing permissions in ${module}")
                def unimpliedPermissions = new HashSet<Permission>(results.get(module));
                existingPerms.each { existingPerm ->
                    results.get(module).each() { loggedPermission ->
                        if (existingPerm.implies(loggedPermission)) {
                            unimpliedPermissions.remove(loggedPermission)
                        }
                    }
                }
                log.info("Adding ${unimpliedPermissions.size()} new permissions to ${module}")
                moduleNode = ModuleUtil.addPerms(module, unimpliedPermissions)
            }
            XmlPrinter.printNode(moduleNode, ModuleUtil.getModuleFile(module))
        }
    }

    static Modes checkMode(String[] args) {
        def s
        try {
            s = args[1]
        } catch (IndexOutOfBoundsException e) {
            return Modes.DEPLOYMENT
        }
        s.toUpperCase() as Modes
    }

    static private Map<String, Set<Permission>> parseLog(String logFile, Modes mode) {
        assert new File(logFile).isFile()
        Map<String, Set<Permission>> results = new LogParser(mode).parseFile(logFile)
        log.info "Found ${results.size()} permissions in log ${logFile}."
        return results;
    }
}
