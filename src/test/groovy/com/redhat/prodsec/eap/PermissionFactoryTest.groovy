package com.redhat.prodsec.eap

import static org.junit.Assert.*;

import org.junit.Test;

import groovy.util.GroovyTestCase;

class PermissionFactoryTest extends GroovyTestCase {

    private static final String JBOSS_HOME_DIR = "jboss.home.dir"
    private static final String JBOSS_HOME_DIR_VALUE = "/some/path"

    private static final String SOME_ENV = "SOME_ENV_THAT_DOES_NOT_EXISTS_EVER!"

    @Override
    public void setUp(){
        super.setUp()
        System.setProperty(JBOSS_HOME_DIR, JBOSS_HOME_DIR_VALUE)
    }
    
    @Test
    public void testSysPropExpansion() {
        def testPermission = PermissionFactory.createPermission("java.io.FilePermission", "\${${JBOSS_HOME_DIR}}/modules", "read")
        assertEquals("${JBOSS_HOME_DIR_VALUE}/modules".toString(), testPermission.getName())
    }
    
    @Test
    public void testEnvDoesNotExist(){
        assertNull(System.getenv(SOME_ENV))
        assertNull(PermissionFactory.createPermission("java.io.FilePermission", "\${env.${SOME_ENV}}", "read"))
    }
}
