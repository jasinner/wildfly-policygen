import Parser

class ParserTestCase extends GroovyTestCase{
    private Pattern pattern

    void setUp(){
        pattern = Parser.p
    }

    void basicMatch(){
        testString = '("java.lang.RuntimePermission" "setClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/'
        Matcher test1 = pattern.matcher(testString)

        assertTrue(test1.hasGroup())
        assertEquals(3, test1.groupCount())
    }

    void fullMatch(){
        def testString = '2016-01-12 12:38:47,439 DEBUG [org.wildfly.security.access] (Controller Boot Thread) Permission check failed (permission "("java.lang.RuntimePermission" "getClassLoader")" in code source "(jar:file:/home/jshepher/apps/product-distributions/modules/system/layers/base/org/jboss/as/controller/main/wildfly-controller-2.0.3.Final-redhat-1.jar!/ <no signer certificates>)" of "ModuleClassLoader for Module "org.jboss.as.controller:main" from local module loader @47089e5f (finder: local module finder @4141d797 (roots: /home/jshepher/apps/product-distributions/modules,/home/jshepher/apps/product-distributions/modules/system/layers/base))")'

        Matcher test = pattern.matcher(testString)

        assertTrue(test.hasGroup())
        assertEquals(3, test.groupCount())
    }

}
