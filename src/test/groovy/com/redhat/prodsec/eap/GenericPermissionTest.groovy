package com.redhat.prodsec.eap

class GenericPermissionTest extends GroovyTestCase{
	private GenericPermission permB
	private GenericPermission permA
	private GenericPermission permC
	private GenericPermission permD
	private GenericPermission permE
	private GenericPermission permF

	@Override
	public void setUp(){
		permA = new GenericPermission("class", "name", "actions")
		permB = new GenericPermission("class", "nameB", "actions")
		permC = new GenericPermission("class", "name", null)
		permD = new GenericPermission("class", "name", "read,write")
		permE = new GenericPermission("class", "name", "read")
		permF = new GenericPermission("class", "name", "read,write,delete")
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
}
