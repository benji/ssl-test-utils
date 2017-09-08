package com.github.benji.ssl.tests.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

//import sun.security.tools.keytool.CertAndKeyGen;
//import sun.security.x509.X500Name;

public class SSLTestsUtils {
	public static String Algorithm = "RSA";

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

	public static X509TrustManager createX509TrustManager(TestCertificate... certs) throws Exception {
		KeyStore keyStore = createTrustStore(certs);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		for (TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				return (X509TrustManager) tm;
			}
		}
		return null;
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
		return createSelfSignedCertificate(name, null);
	}

	public static TestCertificate createSelfSignedCertificate(String name, TestCertificate caCert) throws Exception {
		long start = System.currentTimeMillis();

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(Algorithm, "BC");
		kpGen.initialize(1024, new SecureRandom());
		KeyPair pair = kpGen.generateKeyPair();

		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		x500NameBuilder.addRDN(BCStyle.CN, name);
		X500Name x500Name = x500NameBuilder.build();

		Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		X500Name issuer = x500Name;

		if (caCert != null) {
			issuer = new X509CertificateHolder(caCert.getCertificate().getEncoded()).getSubject();
		}

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
				x500Name, pair.getPublic());

		PrivateKey signingPrivateKey = caCert != null ? caCert.getPrivateKey() : pair.getPrivate();

		ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC")
				.build(signingPrivateKey);
		X509Certificate x509Cert = new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(builder.build(sigGen));

		TestCertificate cert = new TestCertificate();
		cert.setCertificate(x509Cert);
		cert.setName(name);
		cert.setPrivateKey(pair.getPrivate());

		long stop = System.currentTimeMillis();
		System.out.println("Generated cert " + name + " in " + (stop - start) + "ms.");
		return cert;
	}
}
