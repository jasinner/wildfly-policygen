package com.redhat.prodsec.eap

class GenericPermissionTest extends GroovyTestCase{
	private GenericPermission permB
	private GenericPermission permA
	private GenericPermission permC

	@Override
	public void setUp(){
		permA = new GenericPermission("class", "name", "actions")
		permB = new GenericPermission("class", "nameB", "actions")
		permC = new GenericPermission("class", "name", null)
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
}
