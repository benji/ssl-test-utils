package com.github.benji.ssl.tests;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

import junit.framework.TestCase;

public class CertificateAuthorityTest extends TestCase {

	public void testCA() throws Exception {
		// Check the CA trusts itself
		TestCertificate caCert = SSLTestsUtils.createSelfSignedCertificate("Rick", null);
		checkTrusted(caCert, caCert);

		// Check the CA trusts its child
		TestCertificate childCert = SSLTestsUtils.createSelfSignedCertificate("Morty", caCert);
		checkTrusted(caCert, childCert);
	}

	private void checkTrusted(TestCertificate caCert, TestCertificate cert) throws Exception {
		X509TrustManager ts = SSLTestsUtils.createX509TrustManager(caCert);
		ts.checkClientTrusted(new X509Certificate[] { cert.getCertificate() }, SSLTestsUtils.Algorithm);
		ts.checkServerTrusted(new X509Certificate[] { cert.getCertificate() }, SSLTestsUtils.Algorithm);
	}

}
