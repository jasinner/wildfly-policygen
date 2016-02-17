package com.redhat.prodsec.eap

import java.lang.reflect.Constructor
import java.security.Permission
import org.jboss.modules.xml.PolicyExpander
import groovy.util.logging.Log

@Log
class PermissionFactory {

	def static Permission createPermission(String permissionClass, String name, String actions){
		Class<? extends Permission> clazz;
        String expandedName = PolicyExpander.expand(name)
        //If a property can't be expanded in a grant entry, permission entry, or keystore entry, that entry is ignored. 
        //Ref: https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html#PropertyExp
        if(expandedName == null) {
            log.fine("Could not expand EL Expression in ${name}, ignoring permission")
            return null
        }
		try{
			clazz = Class.forName(permissionClass)
			 return constructFromClass(clazz, expandedName, actions)
		} catch(ClassNotFoundException c){
			//Not a class shipped with JSE, just store Permission class name as String
			return new GenericPermission(permissionClass, expandedName, actions)
		}
	}
	
	static private Permission constructFromClass(Class permissionClass, String targetName, String permissionActions){
		final Constructor<? extends Permission> constructor;
		boolean hasTarget = targetName != null && ! targetName.isEmpty();
		boolean hasAction = permissionActions != null && ! permissionActions.isEmpty();
		if (hasTarget && hasAction) {
			Constructor<? extends Permission> test;
			try {
				test = permissionClass.getConstructor(String.class, String.class);
			} catch (NoSuchMethodException ignored) {
				try {
					test = permissionClass.getConstructor(String.class);
					hasAction = false;
				} catch (NoSuchMethodException ignored2) {
					test = permissionClass.getConstructor();
					hasTarget = false;
					hasAction = false;
				}
			}
			constructor = test;
		} else if (hasTarget) {
			assert ! hasAction;
			Constructor<? extends Permission> test;
			try {
				test = permissionClass.getConstructor(String.class);
			} catch (NoSuchMethodException ignored) {
				try {
					test = permissionClass.getConstructor(String.class, String.class);
					hasAction = true;
				} catch (NoSuchMethodException ignored2) {
					test = permissionClass.getConstructor();
					hasTarget = false;
					hasAction = false;
				}
			}
			constructor = test;
		} else {
			constructor = permissionClass.getConstructor();
		}
		if (hasTarget && hasAction) {
			return constructor.newInstance(targetName, permissionActions);
		} else if (hasTarget) {
			return constructor.newInstance(targetName);
		} else {
			return constructor.newInstance();
		}
	}
}
