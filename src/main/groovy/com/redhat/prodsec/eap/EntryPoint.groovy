package com.redhat.prodsec.eap

import java.security.Permission
import java.security.Permissions

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
			Set<Permission> existingPerms = ModuleUtil.buildPermissions(module)
			if(existingPerms == null){
				moduleNode = ModuleUtil.addPerms(module, results.get(module))
			}else{
				boolean implies = false
                def newPermissions = new HashSet<Permission>();
				existingPerms.each{ existingPerm ->
					results.get(module).each(){ loggedPermission ->
						if(existingPerm.implies(loggedPermission))
							implies = true
					}
					if(!implies)
							newPermissions.add(loggedPermission)
                }
                existingPerms.addAll(newPermissions)
                moduleNode = ModuleUtil.removePermissions(module)
			    moduleNode = ModuleUtil.addPerms(module, existingPerms)
			}
			XmlPrinter.printNode(moduleNode, ModuleUtil.getModuleFile(module))
		}
	}

	static private Map<String, Set<Permission>> parseLog(String logFile){
		assert new File(logFile).isFile()
		Map<String, Set<Permission>> results = LogParser.parseFile(logFile)
		println "saved permissions: " + results.size()
		return results;
	}
}
