package com.redhat.prodsec.jboss

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@ToString
@EqualsAndHashCode
class Permission{
    String module, clazz, name, action
}
