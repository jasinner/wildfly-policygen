package com.redhat.prodsec.eap

import groovy.xml.QName

class ModuleUtil{
    private static final MODULE_PREFIX = '/modules/system/layers/base/'
    private static final MODULE_SUFFIX = '/main/module.xml'
    public static final EAP_HOME;

    private static final String MODULE_WITH_PERMISSIONS = 'testData/'

    static{
        EAP_HOME = System.env.'EAP_HOME'
        assert EAP_HOME != null
        assert new File(EAP_HOME).isDirectory()
    }

    def Node readExistingModule(String modulePath){
        def moduleFile = getModuleFile(modulePath)
        def parser = new XmlParser()
        def module = parser.parse(moduleFile)
        assert module.name().toString() == "{urn:jboss:module:1.3}module"
        return module
    }

    def File getModuleFile(String modulePath){
        def moduleFile = new File(EAP_HOME + MODULE_PREFIX + modulePath + MODULE_SUFFIX)
        assert moduleFile.isFile()
        return moduleFile;
    }

    def Node updatePerms(String module, Set newPermissions){
        def node = readExistingModule(module)
        if(hasPermissions(node)){
            node = removePermissions(node)
        }
        node.appendNode(new QName("urn:jboss:module:1.3", "permissions"))
        newPermissions.each{ perm->
            perm.asNode(node.permissions)
        }
        return node
    }

    def boolean hasPermissions(Node root){
        NodeList permissions = getPermissionsNode(root)
        return permissions.size() > 0
    }

    private Node removePermissions(Node root){
        NodeList permissionNodes = getPermissionsNode(root)
        Iterator nodeIter = permissionNodes.iterator()
        while(nodeIter.hasNext()){
            root.remove(nodeIter.next())
        }
        return root
    }

    private NodeList getPermissionsNode(Node root){
        return root.getAt(new QName("urn:jboss:module:1.3", "permissions"))
    }

    def Set buildPermissions(Node root){
        assert hasPermissions(root)
        String module = root.@name
        def grants = root.permissions.grant
        Set results = new HashSet()
        grants.each{
            results.add(new ModulePermission(module:"module",
                clazz: it.@permission,
                name: it.@name,
                action: it.@actions)
            )
        }
        return results
    }
}
