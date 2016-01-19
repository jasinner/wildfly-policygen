package com.redhat.prodsec.jboss

import com.redhat.prodsec.jboss.Permission

class Grouper{
    Set permissions
    Map permissionByModule

    static{
        testGrouper()
    }

    Grouper(Set permissions){
        assert permissions != null
        this.permissions = permissions
        this.permissionByModule = permissions.groupBy({perm -> perm.module})
    }

    static def testGrouper(){
        Set testSet = new HashSet()
        testSet.add(createPerm("org/jboss/as/jpa",
            "java.io.FilePermission",
            "/some/file/path",
            "read")
        )
        testSet.add(createPerm("org/jboss/as/jpa",
            "java.lang.RuntimePermission",
            "setClassLoader",
            null)
        )
        Grouper grouper = new Grouper(testSet)
        assert grouper.permissionByModule.size() == 1
        List jpaPermissions = grouper.permissionByModule.get("org/jboss/as/jpa")
        assert jpaPermissions instanceof ArrayList
        assert jpaPermissions.size() == 2
    }

    static def Permission createPerm(String module, String clazz, String name, String action){
        return new Permission(module: module,
                            clazz: clazz,
                            name: name,
                            action: action
                            )
    }
}
