package com.redhat.prodsec.jboss

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@ToString
@EqualsAndHashCode
class Permission{

    String module, clazz, name, action

    def Node asNode(Node parent){
        Map attributes = [permission:clazz, name:name]
        if(action != null){
            attributes.put("actions", action)
        }
        return new Node(parent, "grant", attributes)
    }
}
