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

    def Node readExistingModule(String modulePath){
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

    def Node addPerms(String module, Set<Permission> newPermissions){
        def node = readExistingModule(module)
        assert !hasPermissions(node)
        node.appendNode(new QName("urn:jboss:module:1.3", "permissions"))
        newPermissions.each{ perm->
            asNode(perm, node.permissions)
        }
        return node
    }
	
	private static Node asNode(Permission permission, Node parent){
		Map attributes = [permission.getClass().getName(), permission.getName()]
		def actions = permission.getActions()
		if(actions != null){
			attributes.put("actions", actions)
		}
		return new Node(parent, "grant", attributes)
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

    public Set<Permission> buildPermissions(String moduleName){
		Node root = readExistingModule(moduleName)
        if(!(hasPermissions(root)))
			return null
        String module = root.@name
        def grants = root.permissions.grant
        Set results = new HashSet<Permission>()
        grants.each{
            results.add(new PermissionFactory(
				module,
                it.@permission,
                it.@name,
                it.@actions)
            )
        }
        return results
    }
}
