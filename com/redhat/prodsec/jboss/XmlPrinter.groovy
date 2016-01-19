package com.redhat.prodsec.jboss

import com.redhat.prodsec.Grouper

class XmlPrinter(){
    Node root

    static{
        
    }

    XmlPrinter(String xmlText){
        def parser = new XmlParser()
        module = parser.parseText(xmlText)
    }

    def String printModule(){
        return XmlUtil.serialize(root)
    }
}
