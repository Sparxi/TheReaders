package com.example.thereaders;

import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;

import javax.xml.XMLConstants;
import java.io.*;

public class Signer extends AbstractTest {
	public void sign() {

		String xmlPath = "./files/readers.xml";
		String xsdPath = "./files/schema.xsd";
		String xsltPath = "./files/styleSheet.xsl";
		String signedPath = "./files/signed.xml";

		XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		dSigner.setLanguage("sk");

		String DEFAULT_XSD_REF = XMLConstants.W3C_XML_SCHEMA_NS_URI;
		String DEFAULT_XSLT_REF = "http://www.w3.org/1999/XSL/Transform";

		XmlPlugin xmlPlugin = new XmlPlugin();
		DataObject xmlObject;
		try {
			xmlObject = xmlPlugin.createObject2("XML",
					"XML",
					readResource(xmlPath),
					readResource(xsdPath),
					"http://www.example.org/sipvs",
					DEFAULT_XSD_REF,
					readResource(xsltPath),
					DEFAULT_XSLT_REF,
					"HTML");
		} catch (
				IOException e) {
			e.printStackTrace();
			return;
		}

		if (xmlObject == null) {
			System.out.println("XMLPlugin.createObject() errorMessage=" + xmlPlugin.getErrorMessage());
			return;
		}

		int rc = dSigner.addObject(xmlObject);
		if (rc != 0) {
			System.out.println("XadesSig.addObject() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}

		rc = dSigner.sign20("signatureId20", "http://www.w3.org/2001/04/xmlenc#sha256", "urn:oid:1.3.158.36061701.1.2.2", "dataEnvelopeId",
				"dataEnvelopeURI", "dataEnvelopeDescr", xadesSig -> {
					if (xadesSig.getErrorMessage() != null)
					{
						System.out.println("XadesSig.sign20() close="+xadesSig.getErrorMessage());
					}
					else {

						try {
							String result = xadesSig.getSignedXmlWithEnvelope();
							BufferedWriter writer = new BufferedWriter(new FileWriter("signed_xml.xml"));
							writer.write(result);
							writer.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				});
		if (rc != 0) {
			System.out.println("XadesSig.sign20() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}

		System.out.println(dSigner.getSignedXmlWithEnvelope());
		try {
			File file  =  new File(signedPath);
			FileWriter fileWriter = new FileWriter(file);
			fileWriter.write(dSigner.getSignedXmlWithEnvelope());
			fileWriter.flush();
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}