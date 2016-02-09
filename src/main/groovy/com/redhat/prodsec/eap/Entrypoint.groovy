package com.redhat.prodsec.eap

import com.redhat.prodsec.*
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
			Set<Permission> existingPerms = ModUtil.buildPermissions(module)
			if(existingPerms == null){
				moduleNode = ModUtil.addPerms(result.get(it))
			}else{
				boolean implies = false
				existingPerms.each{ existingPerm ->
					result.get(module).each(){
						-> loggedPermission{
							if(existingPerm.implies(loggedPermision))
								implies = true
						}
						if(!implies){
							existingPerms.add(loggedPermission)
							implies = false;
						}
					}
					moduleNode = ModUtil.addPerms(existingPerms)
				}
				XmlPrinter.printNode(moduleNode, ModUtil.getModuleFile(module))
			}
		}
	}

	static private Permissions parseLog(String logFile){
		assert new File(logFile).isFile()
		Set results = LogParser.parseFile(logFile)
		println "saved permissions: " + results.size()
		return results;
	}
}
