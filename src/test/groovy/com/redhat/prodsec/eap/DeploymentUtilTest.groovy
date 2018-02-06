package com.redhat.prodsec.eap

import java.security.Permission

class DeploymentUtilTest extends GroovyTestCase{

    public static final String RUNTIME_XML = """
  <permission>
    <class-name>java.lang.RuntimePermission</class-name>
    <name>getClassLoader</name>
  </permission>"""
    public static final String GENERIC_XML = """
  <permission>
    <class-name>org.hibernate.validator.HibernateValidatorPermission</class-name>
    <name>accessPrivateMembers</name>
  </permission>"""
    def Permission accessPrivateMembers, runtimePermission
    def EXPECTED_PREFIX = '<?xml version="1.0" encoding="UTF-8"?>' + System.getProperty("line.separator") + '<permissions xmlns="http://xmlns.jcp.org/xml/ns/javaee" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/permissions_7.xsd" version="7">'
    def EXPECTED_POSTFIX = System.getProperty("line.separator") + '</permissions>'

    @Override
    void setUp(){
        accessPrivateMembers = new GenericPermission("org.hibernate.validator.HibernateValidatorPermission", "accessPrivateMembers", null)
        runtimePermission = new RuntimePermission("getClassLoader")
    }

    void testGenericPermission(){
        def expected = EXPECTED_PREFIX + GENERIC_XML + EXPECTED_POSTFIX
        doPermissionTest(expected, [accessPrivateMembers] as Set)
    }

    void testNormalPermission(){
        def expected = EXPECTED_PREFIX + RUNTIME_XML + EXPECTED_POSTFIX
        doPermissionTest(expected, [runtimePermission] as Set)
    }

    void test2Permissions(){
        def expected = EXPECTED_PREFIX + GENERIC_XML + RUNTIME_XML + EXPECTED_POSTFIX
        doPermissionTest(expected, [accessPrivateMembers, runtimePermission] as Set)
    }


    private void doPermissionTest(String expected, Set<GenericPermission> permissions) {
        def writer = new StringWriter()
        DeploymentUtil.createPermissions(permissions, writer)
        assertEquals(expected, writer.toString())
    }

}
