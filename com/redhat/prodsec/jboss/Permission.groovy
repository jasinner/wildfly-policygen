package com.redhat.prodsec.jboss

import groovy.transform.EqualsAndHashCode
import java.security.Permission
import java.lang.reflect.Constructor

@EqualsAndHashCode
class Permission{

    String module

    java.security.Permission permission

    public Permission(String module, String permissionClass, String name, String actions){
        System.out.println("permission called with: " + module + permissionClass + name + actions);
        this.module = module
        Class<? extends java.security.Permission> clazz;
        try{
            clazz = Class.forName(permissionClass)
            this.permission = Permission.constructFromClass(clazz, name, actions)
        } catch(ClassNotFoundException c){
            //Not a class shipped with JSE, just store Permission class name as String
            this.permission = new GenericPermission(permissionClass, name, actions)
        }
    }

    def Node asNode(Node parent){
        Map attributes = [permission:permission.getClass().getName(), name:permission.getName()]
        if(action != null){
            attributes.put("actions", permission.getActions())
        }
        return new Node(parent, "grant", attributes)
    }

    static java.security.Permission constructFromClass(Class permissionClass, String targetName, String permissionActions){
        final Constructor<? extends java.security.Permission> constructor;
        boolean hasTarget = targetName != null && ! targetName.isEmpty();
        boolean hasAction = permissionActions != null && ! permissionActions.isEmpty();
        if (hasTarget && hasAction) {
            Constructor<? extends java.security.Permission> test;
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
            Constructor<? extends java.security.Permission> test;
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
