package com.redhat.prodsec.eap

import groovy.xml.MarkupBuilder

import java.security.Permission

class DeploymentUtil {
    static def void createPermissions(Set<Permission> permissions){
        def writer = new FileWriter("permissions.xml")
        def permissionsXml = new MarkupBuilder(writer);
        permissionsXml.setDoubleQuotes(true)
        permissionsXml.'permissions'('xmlns':"http://xmlns.jcp.org/xml/ns/javaee",'xmlns:xsi':"http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation":"http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/permissions_7.xsd",
                "version":"7"){}
        

        writer.flush()


    }
}
