package com.redhat.prodsec.eap

class GenericPermissionTest extends GroovyTestCase{
	def permA, permB, permC, permD, permE, permF, permG

	@Override
	public void setUp(){
		permA = new GenericPermission("class", "name", "actions")
		permB = new GenericPermission("class", "nameB", "actions")
		permC = new GenericPermission("class", "name", null)
		permD = new GenericPermission("class", "name", "read,write")
		permE = new GenericPermission("class", "name", "read")
		permF = new GenericPermission("class", "name", "read,write,delete")
        permG = new GenericPermission("class", "name", null)
	}

	public void testSameObject() {
		assertEquals(permA, permA)
	}

	public void testNameEquals(){
		assertFalse(permA.equals(permB))
	}

	public void testNullActions(){
		assertFalse(permA.equals(permC));
	}

	public void testHashCode(){
		assertFalse(permA.hashCode() == permB.hashCode())
	}

	public void testImplies(){
	   assertTrue(permD.implies(permE))
	}

	public void testImpliesMulti(){
	   assertTrue(permF.implies(permD));
	   assertTrue(permF.implies(permE));
	}

    public void testNullActionsImplies(){
        assertFalse(permC.implies(permA))
        assertNotNull(permG)
        assertTrue(permG.implies(permC))
    }
}
