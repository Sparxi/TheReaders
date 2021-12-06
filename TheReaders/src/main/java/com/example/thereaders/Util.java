package com.example.thereaders;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import it.svario.xpathapi.jaxp.XPathAPI;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;

public class Util {

	public static boolean checkAttributeValue(Element element, String attribute, String expectedValue) {
		String actualValue = element.getAttribute(attribute);
		
		if (actualValue != null && actualValue.equals(expectedValue)) {
			return true;
		}
		return false;
	}
	
	public static boolean checkAttributeValue(Element element, String attribute, List<String> expectedValues) {
		for (String expectedValue : expectedValues) {
			
			if (checkAttributeValue(element, attribute, expectedValue)) {
				return true;
			}
		}
		return false;
	}
	
	public static boolean checkAttributeValue(Element element, String attribute) {
		String actualValue = element.getAttribute(attribute);
		
		if (!actualValue.isEmpty()) {
			return true;
		}
		return false;
	}
	
	public static X509CertificateObject getCertificate(Document document) throws XPathExpressionException, InvalidDocumentException {
		
		Element keyInfoElement = (Element) document.getElementsByTagName("ds:KeyInfo").item(0);
		
		if (keyInfoElement == null) {
			throw new InvalidDocumentException("Error getting certificate: document does not contain an element ds:KeyInfo");
		}
		
		Element x509DataElement = (Element) keyInfoElement.getElementsByTagName("ds:X509Data").item(0);
		
		if (x509DataElement == null) {
			throw new InvalidDocumentException("Error getting certificate: document does not contain an element ds:X509Data");
		}
		
		Element x509Certificate = (Element) x509DataElement.getElementsByTagName("ds:X509Certificate").item(0);

		if (x509Certificate == null) {
			throw new InvalidDocumentException("Error getting certificate: document does not contain an element ds:X509Certificate");
		}
		
		X509CertificateObject certObject = null;
		ASN1InputStream inputStream = null;
		
		try {
			inputStream = new ASN1InputStream(new ByteArrayInputStream(Base64.decode(x509Certificate.getTextContent())));
			ASN1Sequence sequence = (ASN1Sequence) inputStream.readObject();
			certObject = new X509CertificateObject(Certificate.getInstance(sequence));
			
		} catch (java.security.cert.CertificateParsingException e) {
			
			throw new InvalidDocumentException("Could not load certificate");
			
		} catch (IOException e) {
			throw new InvalidDocumentException("Could not load certificate");
		} finally {
			
			closeQuietly(inputStream);
		}

		return certObject;
	}

	public static void closeQuietly(ASN1InputStream inputStream) {
		
		if (inputStream == null) {
			return;
		}
		try {
			inputStream.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static TimeStampToken getTimestampToken(Document document) throws InvalidDocumentException {
		
		TimeStampToken ts_token = null;

		Node timestamp = null;
		Map<String, String> nsMap = new HashMap<>();
		nsMap.put("xades", "http://uri.etsi.org/01903/v1.3.2#");

		try {
			timestamp = XPathAPI.selectSingleNode(document, "//xades:EncapsulatedTimeStamp", nsMap);
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (timestamp == null){
			throw new InvalidDocumentException("Dokument neobsahuje časovú pečiatku !");
		}

		try {
			ts_token = new TimeStampToken(new CMSSignedData(Base64.decode(timestamp.getTextContent())));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ts_token;
	}

	public static X509CRL getCRL(int crl_type) throws InvalidDocumentException {
		
		ByteArrayInputStream crlData = null;
		
		try {
			crlData = getByteArrayInputStream(crl_type);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if (crlData == null){
			throw new InvalidDocumentException("Nie je možné načítať CRL súbor !");
		}

		CertificateFactory certFactory;
		try {
			Security.addProvider(new BouncyCastleProvider());
			certFactory = CertificateFactory.getInstance("X.509", "BC");

		} catch (CertificateException | NoSuchProviderException e) {
			System.out.println(e);
			throw new InvalidDocumentException("Nie je možné vytvoriť inštanciu CertificateFactory !");
		}

		X509CRL crl;

		try {
			crl = (X509CRL) certFactory.generateCRL(crlData);
		} catch (CRLException e) {
			throw new InvalidDocumentException("Nie je možné načítať CRL z dát!");
		}

		return crl;
	}
	
	public static ByteArrayInputStream getDataFromUrl(String url) {
		
		URL urlHandler = null;
		try {
			urlHandler = new URL(url);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = null;
		try {
			is = urlHandler.openStream();
			byte[] byteChunk = new byte[4096];
			int n;

			while ( (n = is.read(byteChunk)) > 0 ) {
				baos.write(byteChunk, 0, n);
			}
		}
		catch (IOException e) {
			System.err.printf ("Failed while reading bytes from %s: %s", urlHandler.toExternalForm(), e.getMessage());
			return null;
		}
		finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return new ByteArrayInputStream(baos.toByteArray());
	}
	
	private static ByteArrayInputStream getByteArrayInputStream(int crl_type) throws IOException {
		return new ByteArrayInputStream(FileUtils.readFileToByteArray(getCRLFile(crl_type)));
	}
	
	private static File getCRLFile(int crl_type) {
		if (crl_type == 1) {
			return new File(System.getProperty("user.dir") + "\\src\\main\\resources\\DTCCACrl.crl");
		}
		if (crl_type == 2) {
			return new File(System.getProperty("user.dir") + "\\src\\main\\resources\\dtctsa.crl");
		}
		else return null;
	}
}
