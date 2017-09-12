package com.github.benji.ssl.tests.utils;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
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
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SSLTestsUtils {
	public static String KeyStoreType = "JKS";
	public static String Provider = "BC";
	public static String Algorithm = "RSA";
	public static String SignatureAlgorithm = "SHA256WithRSAEncryption";

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public static KeyStore createTrustStore(TestCertificate... certs) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KeyStoreType);
		keyStore.load(null, null);
		if (certs != null) {
			for (TestCertificate cert : certs) {
				keyStore.setCertificateEntry(cert.getAlias(), cert.getCertificate());
			}
		}
		return keyStore;
	}

	public static KeyStore createKeyStore(TestCertificate cert) throws Exception {
		KeyStore keyStore = createBlankKeyStore();
		if (cert != null) {
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert.getCertificate();
			keyStore.setKeyEntry(cert.getAlias(), cert.getPrivateKey(), cert.getPassword().toCharArray(), chain);
		}
		return keyStore;
	}

	public static KeyStore createBlankKeyStore() throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KeyStoreType);
		keyStore.load(null, null);
		return keyStore;
	}

	public static void addCertificate(KeyStore keyStore, TestCertificate cert) throws KeyStoreException {
		if (cert != null) {
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert.getCertificate();
			keyStore.setKeyEntry(cert.getAlias(), cert.getPrivateKey(), cert.getPassword().toCharArray(), chain);
		}
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
		return getX509TrustManager(tmf);
	}

	public static X509TrustManager getX509TrustManager(TrustManagerFactory tmf) {
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
		kmf.init(keyStore, cert == null ? null : cert.getPassword().toCharArray());
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

	public static X500Name getX500Name(String name) {
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		x500NameBuilder.addRDN(BCStyle.CN, name);
		return x500NameBuilder.build();
	}

	public static TestCertificate createSelfSignedCertificate(String name, TestCertificate caCert) throws Exception {
		long start = System.currentTimeMillis();

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(Algorithm, Provider);
		kpGen.initialize(1024, new SecureRandom());
		KeyPair pair = kpGen.generateKeyPair();

		Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		X500Name x500Name = getX500Name(name);
		X500Name issuer = x500Name;

		if (caCert != null) {
			issuer = new X509CertificateHolder(caCert.getCertificate().getEncoded()).getSubject();
		}

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
				x500Name, pair.getPublic());

		PrivateKey signingPrivateKey = caCert != null ? caCert.getPrivateKey() : pair.getPrivate();

		ContentSigner sigGen = new JcaContentSignerBuilder(SignatureAlgorithm).setProvider(Provider)
				.build(signingPrivateKey);
		X509Certificate x509Cert = new JcaX509CertificateConverter().setProvider(Provider)
				.getCertificate(builder.build(sigGen));

		TestCertificate cert = new TestCertificate();
		cert.setCertificate(x509Cert);
		cert.setName(name);
		cert.setPrivateKey(pair.getPrivate());

		long stop = System.currentTimeMillis();
		System.out.println("Generated cert " + name + " in " + (stop - start) + "ms.");
		return cert;
	}

	public static X509Certificate readCertificate(Reader reader) throws IOException, CertificateException {
		PEMParser parser = new PEMParser(reader);
		X509CertificateHolder obj = (X509CertificateHolder) parser.readObject();
		parser.close();
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(obj);
	}

	public static void writeCertificate(Writer writer, X509Certificate cert) throws IOException {
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(cert);
		}
	}

}
