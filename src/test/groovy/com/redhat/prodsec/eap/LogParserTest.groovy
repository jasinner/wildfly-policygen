package com.redhat.prodsec.eap;

class LogParserTest extends GroovyTestCase{
	
    public void testModules(){
        testRegex('2016-01-22 14:05:32,958 DEBUG [org.wildfly.security.access] (MSC service thread 1-4) Permission check failed (permission "("org.jboss.as.server.security.ServerPermission" "setCurrentServiceContainer")" in code source "(jar:file:/Users/jasonshepherd/products/middleware-product-distributions/modules/system/layers/base/org/jboss/msc/main/jboss-msc-1.2.6.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('(permission "("java.lang.RuntimePermission" "setClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/')
        testRegex('2016-01-12 12:38:47,439 DEBUG [org.wildfly.security.access] (Controller Boot Thread) Permission check failed (permission "("java.lang.RuntimePermission" "getClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "ModuleClassLoader for Module "org.jboss.as.controller:main" from local module loader @47089e5f (finder: local module finder @4141d797 (roots: /home/jshepher/apps/product-distributions/modules,/home/jshepher/apps/product-distributions/modules/system/layers/base))")')
        testRegex('2016-01-12 12:38:46,566 DEBUG [org.wildfly.security.access] (Periodic Recovery) Permission check failed (permission "("java.io.FilePermission" "/home/jshepher/apps/product-distributions/standalone/data/tx-object-store/ShadowNoFileLockStore/defaultStore" "read")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/transactions/main/wildfly-transactions-10.0.0.CR6-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('2016-01-12 12:38:55,427 DEBUG [org.wildfly.security.access] (MSC service thread 1-7) Permission check failed (permission "("org.jboss.as.controller.security.ControllerPermission" "createCaller")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/jmx/main/wildfly-jmx-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
        testRegex('2016-01-27 15:26:39,405 DEBUG [org.wildfly.security.access] (MSC service thread 1-2) Permission check failed (permission "("javax.management.MBeanPermission" "org.infinispan.stats.impl.CacheContainerStatsImpl#-[jboss.infinispan:component=CacheContainerStats,name="server",type=CacheManager]" "registerMBean")" in code source "(jar:file:/Users/jasonshepherd/products/middleware-product-distributions/modules/system/layers/base/org/jboss/msc/main/jboss-msc-1.2.6.Final-redhat-1.jar!/ <no signer certificates>)" of "null")')
    }

    public void testDeployments(){
        testRegex('2018-02-02 14:30:57,041 DEBUG [org.wildfly.security.access] (default task-3) Permission check failed (permission "("org.hibernate.validator.HibernateValidatorPermission" "accessPrivateMembers")" in code source "(vfs:/content/kitchensink.war/WEB-INF/classes <no signer certificates>)" of "null")', 'deployment')
    }
	
    public testRegex(String testString, String mode = 'modules'){
        LogParser parser = new LogParser(EntryPoint.checkMode(mode))
        parser.resetMatcher(testString)
        while(parser.m.find()){
            def module = parser.m.group('module')
            printf("module: %s%n", module)
            assert module != null
            assert parser.m.group('clazz') != null
            assert parser.m.group('name') != null
            if(parser.m.group('clazz').equals('javax.management.MBeanPermission')){
                assert parser.m.group('name').equals('org.infinispan.stats.impl.CacheContainerStatsImpl#-[jboss.infinispan:component=CacheContainerStats,name="server",type=CacheManager]')
            }
        }
    }
}
