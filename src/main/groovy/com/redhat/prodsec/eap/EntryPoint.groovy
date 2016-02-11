package com.redhat.prodsec.eap

import java.security.Permission
import java.security.Permissions
import groovy.util.logging.Log

@Log
class EntryPoint{


	static void main(String[] args) {
		if(args.length < 1){
			println("Usage 'groovy com/redhat/prodsec/jboss/Entrypoint.groovy <logpath>'")
			System.exit(1)
		}
		Map<String, Set<Permission>> results = parseLog(args[0])
		def moduleToUpdate = results.keySet()
		moduleToUpdate.each{ module ->
			Node moduleNode;
            Set<Permission> permissionsToAdd = results.get(module)
            log.info("Trying to build permission for ${module}")
			Set<Permission> existingPerms = ModuleUtil.buildPermissions(module)
			if(existingPerms == null){
                log.info("Found no existing permissions in ${module}," +
                    "adding ${permissionsToAdd.size()} now")
				moduleNode = ModuleUtil.addPerms(module, permissionsToAdd)
			}else{
                log.info("Found ${existingPerms.size()} existing permissions in ${module}")
                def unimpliedPermissions = new HashSet<Permission>(results.get(module));
				existingPerms.each{ existingPerm ->
					results.get(module).each(){ loggedPermission ->
						if(existingPerm.implies(loggedPermission)){
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

	static private Map<String, Set<Permission>> parseLog(String logFile){
		assert new File(logFile).isFile()
		Map<String, Set<Permission>> results = LogParser.parseFile(logFile)
		log.info "Found ${results.size()} permissions in log ${logFile}."
		return results;
	}
}
