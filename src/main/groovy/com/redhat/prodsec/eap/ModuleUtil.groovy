package com.redhat.prodsec.eap

import groovy.util.Node;
import groovy.xml.QName
import java.security.Permission
import groovy.util.logging.Log
import org.jboss.modules.xml.PolicyExpander

@Log
class ModuleUtil{
    private static final MODULE_PREFIX = '/modules/system/layers/base/'
    private static final MODULE_SUFFIX = '/main/module.xml'
    private static final String JBOSS_HOME_KEY = 'JBOSS_HOME'
    private static final String MODULE_WITH_PERMISSIONS = 'testData/'

    public static final JBOSS_HOME;


    static{
        JBOSS_HOME = System.getenv(JBOSS_HOME_KEY)
        assert JBOSS_HOME != null
        assert new File(JBOSS_HOME).isDirectory()
        System.setProperty('jboss.home.dir', JBOSS_HOME)
        log.info("Set System Property 'jboss.home.dir' to ${JBOSS_HOME}")
    }

    def static Node readExistingModule(String modulePath){
        def moduleFile = getModuleFile(modulePath)
        def parser = new XmlParser()
        def module = parser.parse(moduleFile)
        assert module.name().toString() == "{urn:jboss:module:1.3}module"
        return module
    }

    public static File getModuleFile(String modulePath){
        def moduleFile = new File(JBOSS_HOME + MODULE_PREFIX + modulePath + MODULE_SUFFIX)
        assert moduleFile.isFile()
        return moduleFile;
    }

    def static Node addPerms(String module, Set<Permission> newPermissions){
        def node = readExistingModule(module)
        if (noOfPermissions(node) == 0) {
            node.appendNode(new QName("urn:jboss:module:1.3", "permissions"))
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
        def collapsedName = permission.getName();
        if(clazz.equals('java.io.FilePermission')){
            collapsedName = collapse(collapsedName)
        }
        Map attributes = ["permission": clazz,
		  "name": collapsedName]
		def actions = permission.getActions()
		if(actions != null){
			attributes.put("actions", actions)
		}
		assert parent.size() == 1
		def permissionNode = parent.iterator().next()
		return new Node(permissionNode, "grant", attributes)
	}

    protected static String collapse(String expandedValue){
        def envStart = PolicyExpander.ENV_START
        return expandedValue.replace(JBOSS_HOME, "\${${envStart}${JBOSS_HOME_KEY}}")
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
        return root.getAt(new QName("urn:jboss:module:1.3", "permissions"))
    }

    def static Set<Permission> buildPermissions(String moduleName){
		Node root = readExistingModule(moduleName)
        if(noOfPermissions(root) == 0)
			return null
        String module = root.@name
        def grants = root.permissions.grant
        Set results = new HashSet<Permission>()
        grants.each{
            def permission = PermissionFactory.createPermission(
                it.@permission,
                it.@name,
                it.@actions)
            if(permission != null)
                results.add(permission)
        }
        return results
    }
}
