package com.redhat.prodsec.jboss

import com.redhat.prodsec.jboss.Permission

class Grouper{
    private Set permissions
    Map permissionsByModule

    static{
        testGrouper()
    }

    Grouper(Set permissions){
        assert permissions != null
        this.permissions = permissions
        def mapOfLists = permissions.groupBy({perm -> perm.module})
        permissionsByModule = new LinkedHashMap(mapOfLists.size())
        mapOfLists.keySet().each(){
            permissionsByModule.put(it, mapOfLists.get(it).toSet())
        }
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
        testSet.add(createPerm("org/jboss/as/jpa",
            "java.lang.RuntimePermission",
            "setClassLoader",
            null)
        )
        Grouper grouper = new Grouper(testSet)
        assert grouper.permissionsByModule.size() == 1
        Set jpaPermissions = grouper.permissionsByModule.get("org/jboss/as/jpa")
        assert jpaPermissions instanceof HashSet
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
