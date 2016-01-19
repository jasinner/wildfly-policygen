package com.redhat.prodsec.jboss

import groovy.xml.QName

class XmlManipulator{
    private static final MODULE_PREFIX = '/modules/system/layers/base/'
    private static final MODULE_SUFFIX = '/main/module.xml'
    private static final EAP_HOME;

    private static final String MODULE_WITH_PERMISSIONS = 'testData/'

    static{
        EAP_HOME = System.env.'EAP_HOME'
        assert EAP_HOME != null
        assert new File(EAP_HOME).isDirectory()
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
}
