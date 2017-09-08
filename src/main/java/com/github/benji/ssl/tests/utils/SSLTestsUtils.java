package com.github.benji.ssl.tests.utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
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

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

//import sun.security.tools.keytool.CertAndKeyGen;
//import sun.security.x509.X500Name;

public class SSLTestsUtils {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public static String KEYSTORE_PASSWORD = "KeyStorePassword";

	public static KeyStore createTrustStore(TestCertificate... certs) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		if (certs != null) {
			for (TestCertificate cert : certs) {
				keyStore.setCertificateEntry(cert.getAlias(), cert.getCertificate());
			}
		}
		return keyStore;
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

	public static TrustManager[] createTrustManagers(TestCertificate... certs) throws Exception {
		KeyStore keyStore = createTrustStore(certs);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		return tmf.getTrustManagers();
	}

	public static KeyManager[] createKeyManagers(TestCertificate cert) throws Exception {
		KeyStore keyStore = createKeyStore(cert);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
		return kmf.getKeyManagers();
	}

	public static void initSSLContext(SSLContext context, TestCertificate keyCert,
			TestCertificate... trutedCertificates) throws Exception {
		context.init(createKeyManagers(keyCert),
				trutedCertificates == null ? null : createTrustManagers(trutedCertificates), null);
	}

	public static TestCertificate createSelfSignedCertificate(String name) throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(1024, new SecureRandom());
		KeyPair pair = kpGen.generateKeyPair();

		// Generate self-signed certificate
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, name);

		Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(), serial, notBefore, notAfter,
				builder.build(), pair.getPublic());
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC")
				.build(pair.getPrivate());
		X509Certificate x509Cert = new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(certGen.build(sigGen));
		x509Cert.checkValidity(new Date());
		x509Cert.verify(x509Cert.getPublicKey());

		TestCertificate cert = new TestCertificate();
		cert.setCertificate(x509Cert);
		cert.setName(name);
		cert.setPrivateKey(pair.getPrivate());

		return cert;
	}

}
