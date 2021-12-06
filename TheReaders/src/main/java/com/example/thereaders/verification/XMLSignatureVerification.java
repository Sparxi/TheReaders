package com.example.thereaders.verification;

import org.w3c.dom.Document;

import com.example.thereaders.InvalidDocumentException;
import com.example.thereaders.Util;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;

import it.svario.xpathapi.jaxp.XPathAPI;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLSignatureVerification {

	private static List<String> signatureMethods = new ArrayList<String>(Arrays.asList(
			new String[] {
					"http://www.w3.org/2000/09/xmldsig#dsa-sha1", 
					"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
					"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
					"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
					"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
			}
	));

	private static List<String> canonicalizationMethods = new ArrayList<String>(Arrays.asList(
			new String[] {
					"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
			}
	));

	private static List<String> transformMethods = new ArrayList<String>(Arrays.asList(
			new String[] {
					"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
			}
	));

	private static List<String> digestMethods = new ArrayList<String>(Arrays.asList(
			new String[] {
					"http://www.w3.org/2000/09/xmldsig#sha1", 
					"http://www.w3.org/2001/04/xmldsig-more#sha224",
					"http://www.w3.org/2001/04/xmlenc#sha256",
					"http://www.w3.org/2001/04/xmldsig-more#sha384",
					"http://www.w3.org/2001/04/xmlenc#sha512"
			}
	));
	
	private static List<String> manifestTransformMethods = new ArrayList<String>(Arrays.asList(
			
			new String[] {
					"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
					"http://www.w3.org/2000/09/xmldsig#base64"
			}
	));

	private static final Map<String, String> REFERENCES;

	static {
		REFERENCES = new HashMap<String, String>();
		REFERENCES.put("ds:KeyInfo", "http://www.w3.org/2000/09/xmldsig#Object");
		REFERENCES.put("ds:SignatureProperties", "http://www.w3.org/2000/09/xmldsig#SignatureProperties");
		REFERENCES.put("xades:SignedProperties", "http://uri.etsi.org/01903#SignedProperties");
		REFERENCES.put("ds:Manifest", "http://www.w3.org/2000/09/xmldsig#Manifest");
	}
	
	private static final Map<String, String> DIGEST_ALG;
	
	static {
		DIGEST_ALG = new HashMap<String, String>();
		DIGEST_ALG.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
		DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha224", "SHA-224");
		DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
		DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
		DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
	}
	
	private static final Map<String, String> SIGN_ALG;
	
	static {
		SIGN_ALG = new HashMap<String, String>();
		SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
		SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA/ISO9796-2");
		SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
		SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
		SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
	}

	public static void verifyXMLSignature(Document document) throws InvalidDocumentException{
		
		org.apache.xml.security.Init.init();
		Security.addProvider(new BouncyCastleProvider());
		
		verifySignatureMethodAndCanonicalizationMethod(document); //OK
		System.out.println("ds:SignatureMethod a ds:CanonicalizationMethod - OK");
		
		verifyTransformsAndDigestMethod(document); //OK
		System.out.println("ds:Transforms a ds:DigestMethod - OK");
		
		coreValidation1(document);
		System.out.println("Core Validation - ds:Manifest a ds:DigestValue - OK");
		
		coreValidation2(document);
		System.out.println("Core Validation - ds:SignedInfo a ds:SignatureValue - OK");
		
		verifySignature(document); //OK
		System.out.println("ds:Signature ID a namespace xmlns:ds - OK");
		
		verifySignatureValueId(document); //OK
		System.out.println("ds:SignatureValue ID - OK");
		
		verifySignedInfoReferencesAndAttributeValues(document);
		System.out.println("References, ID types ds:SignedInfo - OK");
		
		verifyKeyInfoContent(document); //OK
		System.out.println("Obsah ds:KeyInfo - OK");
		
		verifySignaturePropertiesContent(document); //OK
		System.out.println("Obsah ds:SignatureProperties - OK");
		
		checkReferenceDSManifest(document); //OK
		System.out.println("Elementy ds:Manifest - OK");
		
		verifyManifestDigestValue(document);
		System.out.println("References ds:Manifest - OK");
	}
	
	// kontrola obsahu ds:SignatureMethod a ds:CanonicalizationMethod
	public static void verifySignatureMethodAndCanonicalizationMethod(Document document) throws InvalidDocumentException {
	
		Element signatureMethod = null;
		try {
			signatureMethod = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:SignatureMethod");
			
		} catch (XPathException e) {
			throw new InvalidDocumentException("Element ds:Signature/ds:SignedInfo/ds:SignatureMethod nebol nájdený !");
		}

		// ds:SignatureMethod
		if (Util.checkAttributeValue(signatureMethod, "Algorithm", signatureMethods) == false) {
			throw new InvalidDocumentException("Atribút Algorithm elementu ds:SignatureMethod neobsahuje URI niektorého z podporovaných algoritmov !");
		}
		
		Element canonicalizationMethod = null;
		try {
			canonicalizationMethod = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod");
		
		} catch (XPathException e) {
			throw new InvalidDocumentException("Element ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod nebol nájdený !");
		}

		// ds:CanonicalizationMethod
		if (Util.checkAttributeValue(canonicalizationMethod, "Algorithm", canonicalizationMethods) == false) {
			throw new InvalidDocumentException("Atribút Algorithm elementu ds:CanonicalizationMethod neobsahuje URI niektorého z podporovaných algoritmov !");
		}
	}
	
	// kontrola obsahu ds:Transforms a ds:DigestMethod
	public static void verifyTransformsAndDigestMethod(Document document) throws InvalidDocumentException {
		
		NodeList transformsElements = null;
		try {
			transformsElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms");
		
		} catch (XPathException e) {
			throw new InvalidDocumentException("Element ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms nebol nájdený !");
		}
		
		for (int i=0; i<transformsElements.getLength(); i++) {
			
			Element transformsElement = (Element) transformsElements.item(i);
			Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(0);
			
			// ds:Transforms Element
			if (Util.checkAttributeValue(transformElement, "Algorithm", transformMethods) == false) {
				throw new InvalidDocumentException("Atribút Algorithm elementu ds:Transforms neobsahuje URI niektorého z podporovaných algoritmov !");
			}
		}

		NodeList digestMethodElements = null;
		try {
			digestMethodElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod");
			
		} catch (XPathException e) {
			throw new InvalidDocumentException("Element ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod nebol nájdený !");
		}
		
		for (int i=0; i<digestMethodElements.getLength(); i++) {
			
			Element digestMethodElement = (Element) digestMethodElements.item(i);
			
			// ds:DigestMethod Element
			if (Util.checkAttributeValue(digestMethodElement, "Algorithm", digestMethods) == false) {
				throw new InvalidDocumentException("Atribút Algorithm elementu ds:DigestMethod neobsahuje URI niektorého z podporovaných algoritmov !");
			}
		}
	}

	// ds:Signature - musí mať Id atribút, musí mať špecifikovaný namespace xmlns:ds
	public static void verifySignature(Document document) throws InvalidDocumentException {
		
		Element signatureElement = (Element) document.getElementsByTagName("ds:Signature").item(0);
		
		if (signatureElement == null) {
			throw new InvalidDocumentException("Element ds:Signature nebol nájdený !");
		}
		
		if (signatureElement.hasAttribute("Id") == false) {
			throw new InvalidDocumentException("Element ds:Signature nemá atribút Id !");
		}
		
		if (Util.checkAttributeValue(signatureElement, "Id") == false) {
			throw new InvalidDocumentException("Atribút Id elementu ds:Signature nemá žiadnu hodnotu !");
		}
		
		if (Util.checkAttributeValue(signatureElement, "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#") == false) {
			throw new InvalidDocumentException("Element ds:Signature nemá správny namespace xmlns:ds !");
		}
	}

	// ds:SignatureValue - musí mať Id atribút
	public static void verifySignatureValueId(Document document) throws InvalidDocumentException {
		
		Element signatureValueElement = (Element) document.getElementsByTagName("ds:SignatureValue").item(0);
		
		if (signatureValueElement == null) {
			throw new InvalidDocumentException("Element ds:SignatureValue nebol nájdený !");
		}
		
		if (signatureValueElement.hasAttribute("Id") == false) {
			throw new InvalidDocumentException("Element ds:SignatureValue nemá atribút Id !");
		}
	}

	/*
	 * Overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type voči profilu XAdES_ZEP pre:
	 *	ds:KeyInfo element,
	 * 	ds:SignatureProperties element,
	 * 	xades:SignedProperties element,
	 *  všetky ostatné referencie v rámci ds:SignedInfo musia byť referenciami na ds:Manifest elementy
	 */
	public static void verifySignedInfoReferencesAndAttributeValues(Document document) throws InvalidDocumentException {
		
		NodeList referencesElements = null;
		try {
			referencesElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference");
		
		} catch (XPathException e) {
			throw new InvalidDocumentException("Element ds:Signature/ds:SignedInfo/ds:Reference nebol nájdený !");
		}
		
		for (int i=0; i<referencesElements.getLength(); i++) {
			
			Element referenceElement = (Element) referencesElements.item(i);
			String uri = referenceElement.getAttribute("URI").substring(1);
			String actualType = referenceElement.getAttribute("Type");
			
			Element referencedElement = null;
			try {
				referencedElement = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(),
						String.format("//ds:Signature//*[@Id='%s']", uri));
				
			} catch (XPathException e) {
				throw new InvalidDocumentException("Error verifying existence of reference in ds:SignedInfo. Error getting element with Id " + uri);
			}
			
			if (referencedElement == null) {
				throw new InvalidDocumentException("Error verifying existence of reference in ds:SignedInfo. Element does exist with Id: " + uri);
			}
			
			String referencedElementName = referencedElement.getNodeName();
			
			if (REFERENCES.containsKey(referencedElementName) == false) {
				throw new InvalidDocumentException("Error verifying the existence of references in ds:SignedInfo. Unknown reference " + referencedElementName);
			}
			
			String expectedReferenceType = REFERENCES.get(referencedElementName);
			
			if (actualType.equals(expectedReferenceType) == false) {
				throw new InvalidDocumentException("Error verifying match of references in ds:SignedInfo. " + actualType + " does not match " + expectedReferenceType);
			}
			
			Element keyInfoReferenceElement = null;
			try {
				keyInfoReferenceElement = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(),
						"//ds:Signature/ds:SignedInfo/ds:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Object']");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(
						"Error verifying the existence of references in ds:SignedInfo." +
						"Error getting element with Type http://www.w3.org/2000/09/xmldsig#Object");
			}
			
			if (keyInfoReferenceElement == null) {
				throw new InvalidDocumentException("No reference in ds:KeyInfo element for ds:Reference element");
			}
			
			Element signaturePropertieReferenceElement = null;
			try {
				signaturePropertieReferenceElement = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(),
						"//ds:Signature/ds:SignedInfo/ds:Reference[@Type='http://www.w3.org/2000/09/xmldsig#SignatureProperties']");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(
						"Error verifying the existence of references in ds:SignedInfo." +
						"Error getting element with Type http://www.w3.org/2000/09/xmldsig#SignatureProperties");
			}
			
			if (signaturePropertieReferenceElement == null) {
				throw new InvalidDocumentException("No reference in ds:SignatureProperties element for ds:Reference element");
			}
			
			Element signedInfoReferenceElement = null;
			try {
				signedInfoReferenceElement = (Element) XPathAPI.selectSingleNode(document.getDocumentElement(),
						"//ds:Signature/ds:SignedInfo/ds:Reference[@Type='http://uri.etsi.org/01903#SignedProperties']");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(
						"Error verifying the existence of references in ds:SignedInfo." +
						"Error getting element with Type http://uri.etsi.org/01903#SignedProperties");
			}
			
			if (signedInfoReferenceElement == null) {
				throw new InvalidDocumentException("No reference in xades:SignedProperties element for ds:Reference element");
			}
		}
	}

	/*
	 * Overenie obsahu ds:KeyInfo:
	 * - musí mať Id atribút,
	 * - musí obsahovať ds:X509Data, ktorý obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName,
	 * - hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte,
	 *   ktorý sa nachádza v ds:X509Certificate
	 */
	public static void verifyKeyInfoContent(Document document) throws InvalidDocumentException {
				
		Element keyInfoElement = (Element) document.getElementsByTagName("ds:KeyInfo").item(0);
		
		if (keyInfoElement == null) {
			throw new InvalidDocumentException("Element ds:Signature nebol nájdený !");
		}
		
		if (keyInfoElement.hasAttribute("Id") == false) {
			throw new InvalidDocumentException("Element ds:Signature neobsahuje atribút Id !");
		}
		
		if (Util.checkAttributeValue(keyInfoElement, "Id") == false) {
			throw new InvalidDocumentException("Atribút Id elementu ds:Signature neobsahuje žiadnu hodnotu !");
		}
		
		Element xDataElement = (Element) keyInfoElement.getElementsByTagName("ds:X509Data").item(0);
		
		if (xDataElement == null) {
			throw new InvalidDocumentException("Element ds:KeyInfo neobsahuje element ds:X509Data !");
		}
		
		Element xCertificateElement = (Element) xDataElement.getElementsByTagName("ds:X509Certificate").item(0);
		Element xIssuerSerialElement = (Element) xDataElement.getElementsByTagName("ds:X509IssuerSerial").item(0);
		Element xSubjectNameElement = (Element) xDataElement.getElementsByTagName("ds:X509SubjectName").item(0);
		
		if (xCertificateElement == null) {
			throw new InvalidDocumentException("Element ds:X509Data neobsahuje element ds:X509Certificate !");
		}

		if (xIssuerSerialElement == null) {
			throw new InvalidDocumentException("Element ds:X509Data neobsahuje element ds:X509IssuerSerial !");
		}
		
		if (xSubjectNameElement == null) {
			throw new InvalidDocumentException("Element ds:X509Data neobsahuje element ds:X509SubjectName !");
		}
		
		Element xIssuerNameElement = (Element) xIssuerSerialElement.getElementsByTagName("ds:X509IssuerName").item(0);
		Element xSerialNumberElement = (Element) xIssuerSerialElement.getElementsByTagName("ds:X509SerialNumber").item(0);
		
		if (xIssuerNameElement == null) {
			throw new InvalidDocumentException("Element ds:X509IssuerSerial neobsahuje element ds:X509IssuerName !");
		}
		
		if (xSerialNumberElement == null) {
			throw new InvalidDocumentException("Element ds:X509IssuerSerial neobsahuje element ds:X509SerialNumber !");
		}
		
		X509CertificateObject certificate = null;
		try {
			certificate = Util.getCertificate(document);
			
		} catch (XPathExpressionException e) {
			throw new InvalidDocumentException("Certifikát X509 nie je možné nájsť v dokumente !");
		}	
		
		String certifIssuerName = certificate.getIssuerX500Principal().toString().replaceAll("ST=", "S=");
		String certifSerialNumber = certificate.getSerialNumber().toString();
		String certifSubjectName = certificate.getSubjectX500Principal().toString();
		
		if (xIssuerNameElement.getTextContent().equals(certifIssuerName) == false) {
			throw new InvalidDocumentException("Element ds:X509IssuerName sa nezhoduje s hodnotou v certifikáte !");
		}
		
		if (xSerialNumberElement.getTextContent().equals(certifSerialNumber) == false) {
			throw new InvalidDocumentException("Element ds:X509SerialNumber sa nezhoduje s hodnotou v certifikáte !");
		}
		
		if (xSubjectNameElement.getTextContent().equals(certifSubjectName) == false) {
			throw new InvalidDocumentException("Element ds:X509SubjectName neobsahuje element ds:X509SerialNumber !");
		}
	}
	
	/*
	 * Overenie obsahu ds:SignatureProperties:
	 * 	- musí mať Id atribút,
	 * 	- musí obsahovať dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos,
	 * 	- obidva ds:SignatureProperty musia mať atribút Target nastavený na ds:Signature
	 */
	public static void verifySignaturePropertiesContent(Document document) throws InvalidDocumentException {
		
		Element signaturePropertiesElement = (Element) document.getElementsByTagName("ds:SignatureProperties").item(0);
		
		if (signaturePropertiesElement == null) {
			throw new InvalidDocumentException("Element ds:SignatureProperties nebol nájdený !");
		}
		
		if (signaturePropertiesElement.hasAttribute("Id") == false) {
			throw new InvalidDocumentException("Element ds:SignatureProperties neobsahuje atribút Id !");
		}
		
		if (Util.checkAttributeValue(signaturePropertiesElement, "Id") == false) {
			throw new InvalidDocumentException("Attribút Id elementu ds:SignatureProperties neobsahuje žiadnu hodnotu !");
		}
		
		Element signatureVersionElement = null;
		Element productInfosElement = null;
		
		for (int i = 0; i < signaturePropertiesElement.getElementsByTagName("ds:SignatureProperty").getLength(); i++) {
			
			Element tempElement = (Element) signaturePropertiesElement.getElementsByTagName("ds:SignatureProperty").item(i);
			
			if (tempElement != null) {
				
				Element tempElement2 = (Element) tempElement.getElementsByTagName("xzep:SignatureVersion").item(0);
				
				if (tempElement2 != null) {
					signatureVersionElement = tempElement2;
				}
				
				else {
					tempElement2 = (Element) tempElement.getElementsByTagName("xzep:ProductInfos").item(0);
				
					if (tempElement != null) {
						productInfosElement = tempElement2;
					}
				}
			}
		}
		
		if (signatureVersionElement == null) {
			throw new InvalidDocumentException("ds:SignatureProperties neobsahuje element ds:SignatureProperty, ktorý má ďalší element xzep:SignatureVersion !");
		}
		
		if (productInfosElement == null) {
			throw new InvalidDocumentException("ds:SignatureProperties neobsahuje element ds:SignatureProperty, ktorý má ďalší element xzep:ProductInfos !");
		}
		
		Element signature = (Element) document.getElementsByTagName("ds:Signature").item(0);
		
		if (signature == null) {
			throw new InvalidDocumentException("Element ds:Signature nebol nájdený !");
		}
		
		String signatureId = signature.getAttribute("Id");
	
		Element sigVerParentElement = (Element) signatureVersionElement.getParentNode();
		Element pInfoParentElement = (Element) productInfosElement.getParentNode();
		
		String targetSigVer = sigVerParentElement.getAttribute("Target");
		String targetPInfo = pInfoParentElement.getAttribute("Target");
		
		if (targetSigVer.equals("#" + signatureId) == false) {
			throw new InvalidDocumentException("Atribút Target elementu xzep:SignatureVersion nie je nastavený na ds:Signature !");
		}
		
		if(targetPInfo.equals("#" + signatureId) == false) {
			throw new InvalidDocumentException("Atribút Target elementu xzep:ProductInfos nie je nastavený na ds:Signature !");
		}
	}

	//	overenie ds:Manifest elementov a referencií v elementoch ds:Manifest
	public static boolean checkReferenceDSManifest(Document document) throws InvalidDocumentException{
		
		NodeList manifestElements = null;
		try {
			manifestElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:Object/ds:Manifest");
			
		} catch (XPathException e) {
			e.printStackTrace();
			throw new InvalidDocumentException("//ds:Signature/ds:Object/ds:Manifest nebol nájdený !");
		}
		
		for (int i=0; i<manifestElements.getLength(); i++) {
			
			Element manifestElement = (Element) manifestElements.item(i);

			// každý ds:Manifest element musí mať Id atribút,
			if (manifestElement.hasAttribute("Id") == false) {
				throw new InvalidDocumentException("Manifest ID nenájdené !");
			}
			
			NodeList referenceElements = null;
			try {
				referenceElements = XPathAPI.selectNodeList(manifestElement, "ds:Reference");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(manifestElement + ": ds:Reference not found !");
			}

			// každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object,
			if (referenceElements.getLength() != 1) {
				throw new InvalidDocumentException(manifestElement + ": multiple ds:Reference !");
			}
			
			NodeList transformsElements = null;
			try {
				transformsElements = XPathAPI.selectNodeList(referenceElements.item(0), "ds:Transforms/ds:Transform");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(manifestElement + ": ds:Transforms/ds:Transform nebol nájdený !");
			}
			
			for (int j=0; j<transformsElements.getLength(); j++) {
				
				Element transformElement = (Element) transformsElements.item(j);
				
				// ds:Transforms musí byť z množiny podporovaných algoritmov pre daný element podľa profilu XAdES_ZEP
				if (Util.checkAttributeValue(transformElement, "Algorithm", manifestTransformMethods) == false) {
					throw new InvalidDocumentException(manifestElement + ":ds:Transforms/ds:Transform - nepodporovaný algoritmus !");
				}
			}
			
			Element digestMethodElement = null;
			try {
				digestMethodElement = (Element) XPathAPI.selectSingleNode(referenceElements.item(0), "ds:DigestMethod");
				
			} catch (XPathException e) {
				throw new InvalidDocumentException(manifestElement + " ds:DigestMethod nebola nájdená !");
			}
			
			// ds:DigestMethod – musí obsahovať URI niektorého z podporovaných algoritmov podľa profilu XAdES_ZEP
			if (!Util.checkAttributeValue(digestMethodElement, "Algorithm", digestMethods)) {
				throw new InvalidDocumentException(manifestElement + " ds:DigestMethod - nepodporovaný algoritmus !");
			}
			
			// overenie hodnoty Type atribútu voči profilu XAdES_ZEP
			if (!Util.checkAttributeValue((Element)referenceElements.item(0), "Type", "http://www.w3.org/2000/09/xmldsig#Object")) {
				throw new InvalidDocumentException(manifestElement + " Type wrong URL !");
			}
		}
		return true;
	}
	
	// Overenie hodnoty ds:DigestValue
	public static boolean verifyManifestDigestValue(Document document) throws InvalidDocumentException{
		NodeList referenceElements = null;
		try {
			referenceElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:Object/ds:Manifest/ds:Reference");
			
		} catch (XPathException e) {}
		
		for (int i=0; i<referenceElements.getLength(); i++) {
			
			Element referenceElement = (Element) referenceElements.item(i);
			String uri = referenceElement.getAttribute("URI").substring(1);
		
			Element objectElement = findByAttributeValue(document, "ds:Object", "Id", uri);
			
			Element digestValueElement = (Element) referenceElement.getElementsByTagName("ds:DigestValue").item(0);
			Element digestMethodlement = (Element) referenceElement.getElementsByTagName("ds:DigestMethod").item(0);

			String digestMethod = digestMethodlement.getAttribute("Algorithm");
			digestMethod = DIGEST_ALG.get(digestMethod);
			
			NodeList transformsElements = referenceElement.getElementsByTagName("ds:Transforms");
			
			for (int j=0; j<transformsElements.getLength(); j++) {
				
				Element transformsElement = (Element) transformsElements.item(j);
				Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(j);
				
				String transformMethod = transformElement.getAttribute("Algorithm");
				
				byte[] objectElementBytes = null;
				
				try {
					objectElementBytes = fromElementToString(objectElement).getBytes();
				
				} catch (TransformerException e) {
					throw new InvalidDocumentException("Error transform to byte !");
				}
				
				if ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".equals(transformMethod)) {
					
					try {
						Canonicalizer canonicalizer = Canonicalizer.getInstance(transformMethod);
						objectElementBytes = canonicalizer.canonicalize(objectElementBytes);
						
					} catch (SAXException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | IOException e) {
						e.printStackTrace();
						throw new InvalidDocumentException("Error canonicalizer !");
					}
				}
				
				if ("http://www.w3.org/2000/09/xmldsig#base64".equals(transformMethod)) {
					objectElementBytes = Base64.decode(objectElementBytes);
				}
				
				MessageDigest messageDigest = null;
				try {
					messageDigest = MessageDigest.getInstance(digestMethod);
					
				} catch (NoSuchAlgorithmException e) {
					throw new InvalidDocumentException("MessageDigest algo doesnt exist !");
				}
				
				String actualDigestValue = new String(Base64.encode(messageDigest.digest(objectElementBytes)));
				String expectedDigestValue = digestValueElement.getTextContent();
				
				if (!expectedDigestValue.equals(actualDigestValue)) {
					throw new InvalidDocumentException("Manifest Reference Digest value not same !");
				}
			}
		}
		return true;
	}

	public static Element findByAttributeValue(Document document, String elementType, String attributeName, String attributeValue) {
		
		NodeList elements = document.getElementsByTagName(elementType);
		
		for (int i=0; i<elements.getLength(); i++) {
			Element element = (Element) elements.item(i);

			if (element.hasAttribute(attributeName) && element.getAttribute(attributeName).equals(attributeValue)) {
				return element;
			}
		}
		return null;
	}
	
	public static String fromElementToString(Element element) throws TransformerException {

		StreamResult result = new StreamResult(new StringWriter());
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.transform(new DOMSource(element), result);
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		
		return result.getWriter().toString();
	}

	// Core validation - dereferencovanie URI, kanonikalizacia a overenie odtlackov
	public static boolean coreValidation1(Document document) throws InvalidDocumentException{
		NodeList referencesElements = null;
		try {
			referencesElements = XPathAPI.selectNodeList(document.getDocumentElement(), "//ds:Signature/ds:SignedInfo/ds:Reference");
		
		} catch (XPathException e) {
			throw new InvalidDocumentException("ds:Signature/ds:SignedInfo/ds:Reference not found");
		}
		
		for (int i=0; i<referencesElements.getLength(); i++) {
			
			Element referenceElement = (Element) referencesElements.item(i);
			String uri = referenceElement.getAttribute("URI").substring(1);
			Element manifestElement = findByAttributeValue(document,"ds:Manifest", "Id", uri);
				
			if (manifestElement == null) {
				continue;
			}
			
			Element digestValueElement = (Element) referenceElement.getElementsByTagName("ds:DigestValue").item(0);
			String expectedDigestValue = digestValueElement.getTextContent();
			Element digestMethodElement = (Element) referenceElement.getElementsByTagName("ds:DigestMethod").item(0);
			
			if (Util.checkAttributeValue(digestMethodElement, "Algorithm", digestMethods) == false) {
				throw new InvalidDocumentException("ds:DigestMethod error");
			}
			
			String digestMethod = digestMethodElement.getAttribute("Algorithm");
			digestMethod = DIGEST_ALG.get(digestMethod);
			
			byte[] manifestElementBytes = null;
					
			try {
				manifestElementBytes = fromElementToString(manifestElement).getBytes();
			
			} catch (TransformerException e) {
				throw new InvalidDocumentException("Core validation error element to string");
			}
			
			NodeList transformsElements = manifestElement.getElementsByTagName("ds:Transforms");
			
			for (int j=0; j<transformsElements.getLength(); j++) {
				
				Element transformsElement = (Element) transformsElements.item(j);
				Element transformElement = (Element) transformsElement.getElementsByTagName("ds:Transform").item(0);
				String transformMethod = transformElement.getAttribute("Algorithm");
				
				if ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".equals(transformMethod)) {
					try {
						Canonicalizer canonicalizer = Canonicalizer.getInstance(transformMethod);
						manifestElementBytes = canonicalizer.canonicalize(manifestElementBytes);
						
					} catch (SAXException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | IOException e) {
						throw new InvalidDocumentException("Core validation canonical error");
					}
				}
			}
			
			MessageDigest messageDigest = null;
			
			try {
				messageDigest = MessageDigest.getInstance(digestMethod);
				
			} catch (NoSuchAlgorithmException e) {
				throw new InvalidDocumentException("Core validation alg error");
			}
			String actualDigestValue = new String(Base64.encode(messageDigest.digest(manifestElementBytes)));

			if (expectedDigestValue.equals(actualDigestValue) == false) {			
				throw new InvalidDocumentException("Core validation error digest not same");
			}
		}
		return true;
	}

	// Core validation - kanonikalizacia
	public static boolean coreValidation2(Document document) throws InvalidDocumentException{
		Element signatureElement = (Element) document.getElementsByTagName("ds:Signature").item(0);
		Element signedInfoElement = (Element) signatureElement.getElementsByTagName("ds:SignedInfo").item(0);
		Element canonicalizationMethodElement = (Element) signedInfoElement.getElementsByTagName("ds:CanonicalizationMethod").item(0);
		Element signatureMethodElement = (Element) signedInfoElement.getElementsByTagName("ds:SignatureMethod").item(0);
		Element signatureValueElement = (Element) signatureElement.getElementsByTagName("ds:SignatureValue").item(0);

		byte[] signedInfoElementBytes = null;
		try {
			signedInfoElementBytes = fromElementToString(signedInfoElement).getBytes();
		} catch (TransformerException e) {
			throw new InvalidDocumentException("Error transform to byte");
		}
		
		String canonicalizationMethod = canonicalizationMethodElement.getAttribute("Algorithm");
		
		try {
			Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationMethod);
			signedInfoElementBytes = canonicalizer.canonicalize(signedInfoElementBytes);
			
		} catch (SAXException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | IOException e) {
			throw new InvalidDocumentException("Error canonicalizer");
		}
		
		X509CertificateObject certificate = null;
		try {
			certificate = Util.getCertificate(document);
			
		} catch (XPathExpressionException e) {
			throw new InvalidDocumentException("Certificate not found");
		}
		
		String signatureMethod = signatureMethodElement.getAttribute("Algorithm");
		signatureMethod = SIGN_ALG.get(signatureMethod);
		
		Signature signer = null;
		try {
			signer = Signature.getInstance(signatureMethod);
			signer.initVerify(certificate.getPublicKey());
			signer.update(signedInfoElementBytes);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e1) {
			throw new InvalidDocumentException("Core validation error");
		}
		
		byte[] signatureValueBytes = signatureValueElement.getTextContent().getBytes();
		byte[] decodedSignatureValueBytes = Base64.decode(signatureValueBytes);
		
		boolean verificationResult = false;
		
		try {
			verificationResult = signer.verify(decodedSignatureValueBytes);
			
		} catch (SignatureException e1) {
			throw new InvalidDocumentException("Core validation error - verification dig sig error");
		}
		
		if (verificationResult == false) {
			throw new InvalidDocumentException("Core validation error - verify ds:SignedInfo, ds:SignatureValue not same");
		}
		return true;
	}
}
