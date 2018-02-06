package com.redhat.prodsec.eap

import groovy.xml.MarkupBuilder

import java.security.Permission

class DeploymentUtil {
    static def void createPermissions(Set<Permission> permissions, Writer writer){
        def permissionsXml = new MarkupBuilder(writer);
        permissionsXml.setDoubleQuotes(true)
        permissionsXml.getMkp().xmlDeclaration(['version':'1.0', 'encoding':'UTF-8'])
        permissionsXml.'permissions'('xmlns':"http://xmlns.jcp.org/xml/ns/javaee",'xmlns:xsi':"http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation":"http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/permissions_7.xsd",
                "version":"7"){
            (permissions).each { p ->
                'permission'(){
                    'class-name'(getClazz(p)){}
                    'name'(p.getName())
                    if(p.getActions())
                        'actions'(p.getActions())
                }
            }
        }


        writer.flush()


    }

    private static String getClazz(Permission p) {
        if (p instanceof GenericPermission)
            return p.clazz
        else
            return p.getClass().getName()

    }
}
