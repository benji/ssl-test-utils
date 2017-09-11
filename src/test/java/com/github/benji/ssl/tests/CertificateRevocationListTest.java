package com.github.benji.ssl.tests;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.github.benji.ssl.tests.utils.CRLTestsUtils;
import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

import junit.framework.TestCase;

public class CertificateRevocationListTest extends TestCase {

	public void testCRLRevocation() throws Exception {
		TestCertificate caCert = SSLTestsUtils.createSelfSignedCertificate("goku");
		TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("gohan", caCert);

		X509CRL crl = CRLTestsUtils.createCRL(caCert, cert);
		assertTrue(crl.isRevoked(cert.getCertificate()));
	}

	public void testTrustManagerRevocation() throws Exception {
		TestCertificate caCert = SSLTestsUtils.createSelfSignedCertificate("goku");
		TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("gohan", caCert);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		KeyStore trustStore = SSLTestsUtils.createTrustStore(caCert);
		X509CRL crl = CRLTestsUtils.createCRL(caCert, cert);

		CRLTestsUtils.initTrustManagerWithCRLs(tmf, trustStore, crl);

		X509TrustManager tm = SSLTestsUtils.getX509TrustManager(tmf);

		try {
			tm.checkClientTrusted(new X509Certificate[] { cert.getCertificate() }, SSLTestsUtils.Algorithm);
			fail("Certificate should have been revoked.");
		} catch (Exception e) {
			System.out.println("Certifiate successfully revoked.");
		}
	}

	public void testWriteCRL() throws Exception {
		TestCertificate caCert = SSLTestsUtils.createSelfSignedCertificate("goku");
		TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("gohan", caCert);

		X509CRL crl = CRLTestsUtils.createCRL(caCert, cert);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		CRLTestsUtils.writeCRL(out, crl);
		System.out.println(new String(out.toByteArray()));
	}

}
