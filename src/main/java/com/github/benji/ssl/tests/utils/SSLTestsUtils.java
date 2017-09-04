package com.github.benji.ssl.tests.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

//import sun.security.tools.keytool.CertAndKeyGen;
//import sun.security.x509.X500Name;

public class SSLTestsUtils {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public static String KEYSTORE_PASSWORD = "KeyStorePassword";

	public static TrustManager[] createTrustManagers(TestCertificate... certs) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		for (TestCertificate cert : certs) {
			keyStore.setCertificateEntry(cert.getAlias(), cert.getCertificate());
		}
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		return tmf.getTrustManagers();
	}

	public static KeyStore createKeyStore(TestCertificate cert) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		if (cert != null) {
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert.getCertificate();
			keyStore.setKeyEntry(cert.getAlias(), cert.getPrivateKey(), KEYSTORE_PASSWORD.toCharArray(), chain);
		}
		return keyStore;
	}

	public static KeyManager[] createKeyManagers(TestCertificate cert) throws Exception {
		KeyStore keyStore = createKeyStore(cert);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
		return kmf.getKeyManagers();
	}

	public static TestCertificate createSelfSignedCertificate(String name) throws Exception {
		// generate a key pair
		long start = System.currentTimeMillis();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(1024, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// build a certificate generator
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("cn=example");

		// add some options
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setSubjectDN(new X509Name("dc=name"));
		certGen.setIssuerDN(dnName); // use the same
		// yesterday
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
		// in 2 years
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

		// finally, sign the certificate with the private key of the same
		// KeyPair
		X509Certificate x509Cert = certGen.generate(keyPair.getPrivate(), "BC");

		TestCertificate cert = new TestCertificate();
		cert.setCertificate(x509Cert);
		cert.setName(name);
		cert.setPrivateKey(keyPair.getPrivate());

		long stop = System.currentTimeMillis();
		System.out.println("Generated cert in " + (stop - start) + "ms.");
		return cert;
	}

	public static void initSSLContext(SSLContext context, TestCertificate keyCert,
			TestCertificate... trutedCertificates) throws Exception {
		context.init(createKeyManagers(keyCert), createTrustManagers(trutedCertificates), null);
	}

}
