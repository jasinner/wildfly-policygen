package com.redhat.prodsec.eap

import groovy.util.Node;
import groovy.xml.QName
import java.security.Permission

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

    def static Node readExistingModule(String modulePath){
        def moduleFile = getModuleFile(modulePath)
        def parser = new XmlParser()
        def module = parser.parse(moduleFile)
        assert module.name().toString() == "{urn:jboss:module:1.3}module"
        return module
    }

    public static File getModuleFile(String modulePath){
        def moduleFile = new File(EAP_HOME + MODULE_PREFIX + modulePath + MODULE_SUFFIX)
        assert moduleFile.isFile()
        return moduleFile;
    }

    def static Node addPerms(String module, Set<Permission> newPermissions){
        def node = readExistingModule(module)
        assert !hasPermissions(node)
        node.appendNode(new QName("urn:jboss:module:1.3", "permissions"))
        newPermissions.each{ perm->
            asNode(perm, node.permissions)
        }
        return node
    }

	private static Node asNode(Permission permission, NodeList parent){
		Map attributes = ["permission": permission.getClass().getName(),
		  "name": permission.getName()]
		def actions = permission.getActions()
		if(actions != null){
			attributes.put("actions", actions)
		}
		assert parent.size() == 1
		def permissionNode = parent.iterator().next()
		return new Node(permissionNode, "grant", attributes)
	}

    def static boolean hasPermissions(Node root){
        NodeList permissions = getPermissionsNode(root)
        return permissions.size() > 0
    }

    def static Node removePermissions(String module){
        def root = readExistingModule(module)
        NodeList permissionNodes = getPermissionsNode(root)
        Iterator nodeIter = permissionNodes.iterator()
        while(nodeIter.hasNext()){
            root.remove(nodeIter.next())
        }
        return root
    }

    private static NodeList getPermissionsNode(Node root){
        return root.getAt(new QName("urn:jboss:module:1.3", "permissions"))
    }

    def static Set<Permission> buildPermissions(String moduleName){
		Node root = readExistingModule(moduleName)
        if(!(hasPermissions(root)))
			return null
        String module = root.@name
        def grants = root.permissions.grant
        Set results = new HashSet<Permission>()
        grants.each{
            results.add(PermissionFactory.createPermission(
                it.@permission,
                it.@name,
                it.@actions)
            )
        }
        return results
    }
}
