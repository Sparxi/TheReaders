package com.example.thereaders;
//package net.codejava.form.functions;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

//import org.jdom2.Document;
//import org.jdom2.Element;
//import org.jdom2.Namespace;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.util.*;
public class TimeStamp {
}

// Overenie casovej peciatky
public class TimestampVerification {


    public boolean verifyTimestamp(X509CRL crl, TimeStampToken ts_token, Element root) throws Exception {

        try {
            verifyTimestampCerfificate(crl, ts_token);
            verifyMessageImprint(ts_token, root);
        } catch (Exception e){
            e.printStackTrace();
        }

        return true;

    }

    // Overenie platnosti certifikatu peciatky voci casu UtcNow a voci poslednemu platnemu CRL
    public boolean verifyTimestampCerfificate(X509CRL crl, TimeStampToken ts_token) throws Exception {

        X509CertificateHolder certificate = null;

        Store<X509CertificateHolder> certHolders = ts_token.getCertificates();
        ArrayList<X509CertificateHolder> certs = new ArrayList<>(certHolders.getMatches(null));

        BigInteger serialNumToken = ts_token.getSID().getSerialNumber();
        X500Name issuerToken = ts_token.getSID().getIssuer();

        for (X509CertificateHolder certHolder : certs) {
            if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)){
                certificate = certHolder;
                break;
            }
        }


        if (certificate == null){
            throw new Exception("Chyba casovej peciatky: V dokumente chyba certifikat casovej peciatky!");
        }

        if (!certificate.isValidOn(new Date())){
            throw new Exception("Chyba casovej peciatky: Podpisovy certifikat casovej peciatky nie je platny voci casu UtcNow.");
        }

        if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null){
            throw new Exception("Chyba casovej peciatky: Podpisovy certifikat casovej peciatky nie je platny voci poslednemu platnemu CRL.");
        }

        return true;

    }

    // Overenie MessageImprint z casovej peciatky voci podpisu ds:SignatureValue
    public boolean verifyMessageImprint(TimeStampToken ts_token, Element root) throws Exception {

        byte[] messageImprint = ts_token.getTimeStampInfo().getMessageImprintDigest();
        String hashAlg = ts_token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Chyba casovej peciatky: Nepodporovany hash algoritmus v MessageImprint.");
        }


        Namespace ns = Namespace.getNamespace("ds",  "http://www.w3.org/2000/09/xmldsig#");
        Element signatureElement = root.getChild("Signature", ns);
        Element signatureValueElement = signatureElement.getChild("SignatureValue", ns);

        if (signatureValueElement == null){
            throw new Exception("Chyba casovej peciatky: Element ds:SignatureValue neexistuje.");
        }

        byte[] signatureValueBytes = signatureValueElement.getText().getBytes();
        byte[] decodedSignatureValueBytes = Base64.decode(signatureValueBytes);


        if (!Arrays.equals(messageImprint, messageDigest.digest(decodedSignatureValueBytes))) {
            throw new Exception("Chyba casovej peciatky: MessageImprint z casovej peciatky a podpis ds:SignatureValue sa nezhodujÃº.");
        }


        return true;

    }
}