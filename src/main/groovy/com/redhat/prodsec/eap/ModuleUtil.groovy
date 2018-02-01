package com.redhat.prodsec.eap

import groovy.util.Node;
import groovy.xml.QName
import java.security.Permission
import groovy.util.logging.Log

@Log
class ModuleUtil{
    private static final MODULE_PREFIX = '/modules/system/layers/base/'
    private static final MODULE_SUFFIX = '/main/module.xml'
    public static final EAP_HOME;

    private static final String MODULE_WITH_PERMISSIONS = 'testData/'

    static{
        EAP_HOME = System.env.'EAP_HOME'
        assert EAP_HOME != null
        assert new File(EAP_HOME).isDirectory()
        System.setProperty('jboss.home.dir', EAP_HOME)
        log.info("Set System Property 'jboss.home.dir' to ${EAP_HOME}")
    }

    def static Node readExistingModule(String modulePath){
        def moduleFile = getModuleFile(modulePath)
        def parser = new XmlParser()
        def module = parser.parse(moduleFile)
        assert module.name().toString().endsWith("module")
        return module
    }

    public static File getModuleFile(String modulePath){
        def moduleFile = new File(EAP_HOME + MODULE_PREFIX + modulePath + MODULE_SUFFIX)
        assert moduleFile.isFile()
        return moduleFile;
    }

    def static Node addPerms(String module, Set<Permission> newPermissions){
        def node = readExistingModule(module)
        if (noOfPermissions(node) == 0) {
            node.appendNode(new QName("urn:jboss:module:1.5", "permissions"))
        }
        newPermissions.each{ perm->
            asNode(perm, node.permissions)
        }
        return node
    }

	private static Node asNode(Permission permission, NodeList parent){
        def clazz
        if(permission instanceof GenericPermission)
            clazz = permission.clazz
        else
            clazz = permission.getClass().getName()
        Map attributes = ["permission": clazz,
		  "name": permission.getName()]
		def actions = permission.getActions()
		if(actions != null){
			attributes.put("actions", actions)
		}
		assert parent.size() == 1
		def permissionNode = parent.iterator().next()
		return new Node(permissionNode, "grant", attributes)
	}

    def static int noOfPermissions(Node root){
        NodeList permissions = getPermissionsNode(root)
        return permissions.size()

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
        return root.getAt(new QName("urn:jboss:module:1.5", "permissions"))
    }

    def static Set<Permission> buildPermissions(String moduleName){
		Node root = readExistingModule(moduleName)
        if(noOfPermissions(root) == 0)
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
