package com.example.thereaders;

import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;

public class TestM extends AbstractTest {

	public static void main(String[] args) throws Exception {
		int rc;

		final XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		//dSigner.setLanguage("sk");

		XmlPlugin xmlPlugin = new XmlPlugin();
		DataObject xmlObject = xmlPlugin.createObject("XML1", "XML", readResource("xml/UI_26_vin_neobmedz/form.108.xml"),
				readResource("xml/UI_26_vin_neobmedz/form.108.xsd"),
				"http://www.egov.sk/mvsr/NEV/datatypes/Zapis/Ext/PodanieZiadostiOPrihlasenieImporteromSoZepUI.1.0.xsd", "http://www.example.com/xml/sb",
				readResource("xml/UI_26_vin_neobmedz/form.108.sb.xslt"), "http://www.example.com/xml/sb");

		if (xmlObject == null) {
			System.out.println("XMLPlugin.createObject() errorMessage=" + xmlPlugin.getErrorMessage());
			return;
		}

		rc = dSigner.addObject(xmlObject);
		if (rc != 0) {
			System.out.println("XadesSig.addObject() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}

		rc = dSigner.sign20("signatureId20", "http://www.w3.org/2001/04/xmlenc#sha256", "urn:oid:1.3.158.36061701.1.2.2", "dataEnvelopeId",
				"dataEnvelopeURI", "dataEnvelopeDescr");
		if (rc != 0) {
			System.out.println("XadesSig.sign20() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}		

		System.out.println(dSigner.getSignedXmlWithEnvelope());
	}
}