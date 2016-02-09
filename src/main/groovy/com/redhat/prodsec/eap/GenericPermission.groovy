package com.redhat.prodsec.eap

import java.lang.UnsupportedOperationException
import org.codehaus.groovy.util.HashCodeHelper
import java.security.Permission


public class GenericPermission extends Permission{
    String clazz, actions

    public GenericPermission(String clazz, String name, String actions){
        super(name);
        this.clazz = clazz;
        this.actions = actions;
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
		if (actions != otherPerm.actions) return false
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
        //TODO: would be better to split actions and compare
        return this.equals(perm);
    }

    @Override
    public String getActions(){
        return this.actions
    }
	
    private boolean canEqual(java.lang.Object other) {
    	return other instanceof GenericPermission
    }
}