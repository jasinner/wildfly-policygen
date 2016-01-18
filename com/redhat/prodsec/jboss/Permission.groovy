package com.redhat.prodsec.jboss

import groovy.transform.EqualsAndHashCode

@EqualsAndHashCode
class Permission{
    String module, clazz, permission, action
}