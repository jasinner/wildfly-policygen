package com.redhat.prodsec.eap

import groovy.xml.XmlUtil
import javax.xml.parsers.SAXParser
import javax.xml.XMLConstants
import org.xml.sax.InputSource

class XmlPrinter{

    static def printNode(Node root, File moduleFile){
        def outstream = new FileOutputStream(moduleFile, false)
        XmlUtil.serialize(root, outstream)
    }

    static public String printNode(Node root){
        return XmlUtil.serialize(root)
    }
}
