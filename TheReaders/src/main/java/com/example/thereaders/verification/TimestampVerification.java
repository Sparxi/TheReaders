package com.example.thereaders.verification;

import org.w3c.dom.Document;

import com.example.thereaders.InvalidDocumentException;
import com.example.thereaders.Util;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.xml.xpath.XPathException;
import it.svario.xpathapi.jaxp.XPathAPI;
import org.w3c.dom.Node;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tsp.TimeStampToken;

public class TimestampVerification {

	public static void verifyTimestamp(Document document) throws InvalidDocumentException{

		X509CRL crl = Util.getCRL(2);
		TimeStampToken token = Util.getTimestampToken(document);
		
		verifyTimestampCerfificate(crl, token);
		verifyMessageImprint(token, document);

		System.out.println("References ds:Manifest - OK");
	}

	//	Overenie voči UTC NOW a CRL
	public static void verifyTimestampCerfificate(X509CRL crl, TimeStampToken ts_token) throws InvalidDocumentException {
		X509CertificateHolder signer = null;

		Store<X509CertificateHolder> certHolders = ts_token.getCertificates();
		ArrayList<X509CertificateHolder> certList = new ArrayList<>(certHolders.getMatches(null));

		BigInteger serialNumToken = ts_token.getSID().getSerialNumber();
		X500Name issuerToken = ts_token.getSID().getIssuer();

		for (X509CertificateHolder certHolder : certList) {
			if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)){
				signer = certHolder;
				break;
			}
		}

		if (signer == null){
			throw new InvalidDocumentException("Chyba časovej pečiatky: V dokumente chýba podpisový certifikát časovej pečiatky !");
		}

		// UTC NOW
		if (!signer.isValidOn(new Date())){
			throw new InvalidDocumentException("Chyba časovej pečiatky: Podpisový ceritifkát časovej pečiatky nie je platný voči času UTC NOW !");
		}

		System.out.println("Overenie platnosti podpisového certifikátu časovej pečiatky voči času UTC NOW - OK");

		// CRL
		if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
			throw new InvalidDocumentException("Chyba časovej pečiatky: Podpisový ceritifkát časovej pečiatky nie je platný voči poslednému platnému CRL !");
		}

		System.out.println("Overenie platnosti podpisového certifikátu časovej pečiatky voči času CRL - OK");
	}

	//	Overenie MessageImprint voči podpisu ds:SignatureValue
	public static void verifyMessageImprint(TimeStampToken ts_token, Document document) throws InvalidDocumentException {

		byte[] messageImprint = ts_token.getTimeStampInfo().getMessageImprintDigest();
		String hashAlgo = ts_token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

		Map<String, String> nsMap = new HashMap<>();
		nsMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");

		Node signatureValueNode = null;

		try {
			signatureValueNode = XPathAPI.selectSingleNode(document, "//ds:Signature/ds:SignatureValue", nsMap);
		} catch (XPathException e) {
			e.printStackTrace();
		}

		if (signatureValueNode == null){
			throw new InvalidDocumentException("Chyba časovej pečiatky: Element ds:SignatureValue nebol nájdený.");
		}

		byte[] signatureValue = Base64.decode(signatureValueNode.getTextContent().getBytes());

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance(hashAlgo, "BC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new InvalidDocumentException("Chyba časovej pečiatky: Nepodporovaný hash algoritmus v message digest.");
		}

		if (!Arrays.equals(messageImprint, messageDigest.digest(signatureValue))){
			throw new InvalidDocumentException("Chyba časovej pečiatky: MessageImprint z časovej pečiatky a podpis ds:SignatureValue sa nezhodujú !");
		}

		System.out.println("Porovnanie MessageImprint z časovej pečiatky a ds:SignatureValue - OK");
	}
}
