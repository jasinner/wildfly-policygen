package com.redhat.prodsec.eap

import java.lang.UnsupportedOperationException
import org.codehaus.groovy.util.HashCodeHelper
import java.security.Permission
import java.security.PermissionCollection


public class GenericPermission extends Permission{
    String clazz
	List<String> actions

    public GenericPermission(String clazz, String name, String actions){
        super(name);
        this.clazz = clazz;
        if(actions != null)
            this.actions = actions.tokenize(",");
    }

	@Override
	public boolean equals(Object other){
		if (other == null) return false
		if (this.is(other)) return true
		if (!(other instanceof GenericPermission)) return false
		if (!other.canEqual(this)) return false
		def otherPerm = (GenericPermission) other
		if (getName() != otherPerm.getName()) return false
		if (clazz != otherPerm.clazz) return false
		if (getActions() != otherPerm.getActions()) return false
		return true
	}

	@Override
	public int hashCode(){
		int hashcode = HashCodeHelper.initHash()
		hashcode = HashCodeHelper.updateHash(hashcode, getName())
		hashcode = HashCodeHelper.updateHash(hashcode, clazz)
		return HashCodeHelper.updateHash(hashcode, actions)
	}

    @Override
    public boolean implies(Permission perm){
        if(perm == null) return false
		if(this.is(perm)) return true
		if (getName() != perm.getName()) return false
		if (!(perm instanceof GenericPermission)) return false
		if(clazz != perm.clazz) return false
        if(actions == null && perm.getActionsList() == null) return true
        if(actions != null) {
		      if(actions.containsAll(perm.getActionsList()))
                return true
        }
        return false
    }

    public List<String> getActionsList(){
        return this.actions;
    }

    @Override
    public String getActions(){
        if(actions == null || actions.equals('')) return
		def sb = new StringBuilder();
		actions.each() {
			sb.append(it).append(',')
		}
		def newActions = sb.toString()
        return newActions.substring(0, sb.length() -  1);
    }

    private boolean canEqual(java.lang.Object other) {
    	return other instanceof GenericPermission
    }
}