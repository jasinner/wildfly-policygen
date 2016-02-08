package com.redhat.prodsec.jboss

import java.lang.UnsupportedOperationException
import groovy.transform.EqualsAndHashCode

@EqualsAndHashCode(includeFields=true)
public class GenericPermission extends java.security.Permission{
    String clazz, actions

    public GenericPermission(String clazz, String name, String actions){
        super(name);
        this.clazz = clazz;
        this.actions = actions;
    }

    @Override
    public boolean implies(java.security.Permission perm){
        //TODO: would be better to split actions and compare
        return this.equals(perm);
    }

    @Override
    public String getActions(){
        return this.actions
    }
}