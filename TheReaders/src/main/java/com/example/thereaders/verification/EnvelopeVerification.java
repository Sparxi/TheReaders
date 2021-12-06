package com.example.thereaders.verification;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import com.example.thereaders.InvalidDocumentException;
import com.example.thereaders.Util;

public class EnvelopeVerification {

	public static void verifyEnvelope(Document document) throws InvalidDocumentException{
		Element root = document.getDocumentElement();

		if (!Util.checkAttributeValue(root, "xmlns:xzep", "http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0")) {
			throw new InvalidDocumentException(
					"Koreňový element musí obsahovať atribút xmlns:xzep s hodnotou http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0");
		}
		System.out.println("xmlns:xzep - OK");

		if (!Util.checkAttributeValue(root, "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")) {
			throw new InvalidDocumentException(
					"Koreňový element musí obsahovať atribút xmlns:ds s hodnotou http://www.w3.org/2000/09/xmldsig#");
		}
		System.out.println("xmlns:ds - OK");

		System.out.println("Overenie dátovej obálky prebehlo úspešne !");
	}
}
