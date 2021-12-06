package com.example.thereaders;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.example.thereaders.verification.TimestampVerification;
import com.example.thereaders.verification.EnvelopeVerification;
import com.example.thereaders.verification.CertificateVerification;
import com.example.thereaders.verification.XMLSignatureVerification;

public class DocumentVerificator {
	
	private static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>";
	private static final String UTF8_BOM = "\uFEFF";
	
	private File[] documents = null;

	public DocumentVerificator() {
		File directory = new File(System.getProperty("user.dir") + "\\src\\main\\resources\\documents");
		documents = directory.listFiles();
	}
	
	public DocumentVerificator verifyDocuments() {

        for (File f : documents) {
            System.out.println(f.getName());
            
            String documentContent = null;
			try {
				documentContent = readFile(f.getPath());
				documentContent = removeUTF8BOM(documentContent);
				documentContent = addXMLHeader(documentContent);
	
			} catch (IOException e) {
				System.out.println("Cannot open or read " + f.getPath() + e);
				continue;
			}
           
            Document document = null;
            
			try {
				document = convertToDocument(documentContent);
				
			} catch (Exception e) {
				System.out.println("Cannot parse " + f.getPath() + " content into org.w3c.dom.Document" + e);
				continue;
			}
            
            try {
				verify(document);
				System.out.println("Súbor " + f.getName() + " je validný !\n");

			} catch (InvalidDocumentException | XPathExpressionException e) {
				System.out.println("Súbor " + f.getName() + " nie je validný !\n" + e.getMessage()+ "\n");
			}
        }
		return null;
	}
	
	public void verify(Document document) throws InvalidDocumentException, XPathExpressionException {
		EnvelopeVerification.verifyEnvelope(document);
		XMLSignatureVerification.verifyXMLSignature(document);
		TimestampVerification.verifyTimestamp(document);
		CertificateVerification.verifyCertificate(document);
	}
	
	private String readFile(String filePath) throws IOException {
		
		byte[] encoded = Files.readAllBytes(Paths.get(filePath));
		return new String(encoded, Charset.defaultCharset());
	}
	
	private String removeUTF8BOM(String s) {
	
		if (s.startsWith(UTF8_BOM)) {
	        s = s.substring(1);
	    }
	    return s;
	}
	
	// XML subory nemaju prvy XML tag
	private String addXMLHeader(String s) {
		
		if (s.startsWith("<?xml") == false) {	
			s = XML_HEADER + s;
		}
		return s;
	}

	private Document convertToDocument(String s) throws Exception {
		
		DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
		documentFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
		InputSource source = new InputSource(new StringReader(s));
		
		return documentBuilder.parse(source);
	}
}
