package com.redhat.prodsec.jboss

import groovy.xml.QName

class XmlManipulator{
    private static final MODULE_PREFIX = '/modules/system/layers/base/'
    private static final MODULE_SUFFIX = '/main/module.xml'
    private static final EAP_HOME;

    private static final String MODULE_WITH_PERMISSIONS = '''<module xmlns="urn:jboss:module:1.3" name="org.jboss.as.server">
    <properties>
        <property name="jboss.api" value="private"/>
        <property name="jboss.require-java-version" value="1.8"/>
    </properties>

    <main-class name="org.jboss.as.server.DomainServerMain"/>

    <resources>
        <resource-root path="wildfly-server-2.0.6.Final-SNAPSHOT.jar"/>
    </resources>

    <permissions>
      <grant permission="java.lang.RuntimePermission" name="getBootModuleLoader"/>
      <grant permission="java.lang.RuntimePermission" name="addURLStreamHandlerFactory"/>
      <grant permission="java.lang.RuntimePermission" name="getClassLoader"/>
      <grant permission="java.lang.RuntimePermission" name="getenv.*"/>
      <grant permission="java.lang.RuntimePermission" name="shutdownHooks"/>
      <grant permission="java.util.PropertyPermission" name="*" actions="read,write"/>
      <grant permission="java.io.FilePermission" name="${jboss.home.dir}/-" actions="read"/>
      <grant permission="java.io.FilePermission" name="${jboss.home.dir}" actions="read"/>
      <!--TODO use system property eg:
      <grant permission="java.io.FilePermission" name="${jboss.home.dir}/-" actions="read"/>-->
    </permissions>
</module>'''

    static{
        EAP_HOME = System.env.'EAP_HOME'
        assert EAP_HOME != null
        assert new File(EAP_HOME).isDirectory()
        testModuleWithPermissions()
    }

    def Node readExistingModule(String modulePath){
        def parser = new XmlParser()
        def moduleFile = new File(EAP_HOME + MODULE_PREFIX + modulePath + MODULE_SUFFIX)
        assert moduleFile.isFile()
        def module = parser.parse(moduleFile)
        assert module.name().toString() == "{urn:jboss:module:1.3}module"
        return module
    }

    def boolean hasPermissions(Node root){
        NodeList permissions = getPermissionsNode(root)
        return permissions.size() > 0
    }

    def NodeList getPermissionsNode(Node root){
        return root.getAt(new QName("urn:jboss:module:1.3", "permissions"))
    }

    def Set buildPermissions(Node root){
        assert hasPermissions(root)
        String module = root.@name
        def grants = root.permissions.grant
        Set results = new HashSet()
        grants.each{
            results.add(new Permission(module:"module",
                clazz: it.@permission,
                name: it.@name,
                action: it.@actions)
            )
        }
    }

    private static def testModuleWithPermissions(){
        def parser = new XmlParser()
        def module = parser.parseText(MODULE_WITH_PERMISSIONS)
        def test = new XmlManipulator()
        assert test.hasPermissions(module)
        assert test.buildPermissions(module).size() == 8
    }
}
