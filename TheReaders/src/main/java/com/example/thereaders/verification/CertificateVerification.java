package com.example.thereaders.verification;

import com.example.thereaders.InvalidDocumentException;
import com.example.thereaders.Util;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import javax.xml.xpath.XPathExpressionException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

public class CertificateVerification {

	public static void verifyCertificate(Document document) throws InvalidDocumentException, XPathExpressionException {
		
		X509CRL crl = Util.getCRL(1);
		TimeStampToken timeStampToken = Util.getTimestampToken(document);
		X509CertificateObject certificateObject = Util.getCertificate(document);

		try {
			certificateObject.checkValidity(timeStampToken.getTimeStampInfo().getGenTime());
		} catch (CertificateExpiredException e) {
			throw new InvalidDocumentException("Platnosť podpisového certifikátu vypršala v čase podpísania !");
		} catch (CertificateNotYetValidException e) {
			throw new InvalidDocumentException("Certifikát v čase podpísania ešte nebol platný !");
		}

		X509CRLEntry entry = crl.getRevokedCertificate(certificateObject.getSerialNumber());
			if (entry != null && timeStampToken.getTimeStampInfo().getGenTime().after(entry.getRevocationDate())) {
			throw new InvalidDocumentException("Certifikát bol v čase podpísania zrušený !");
		}
			System.out.println("Platnosť certifikátu - OK");
	}
}
