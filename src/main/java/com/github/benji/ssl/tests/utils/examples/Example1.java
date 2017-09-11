package com.github.benji.ssl.tests.utils.examples;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

public class Example1 {

	public static void main(String[] args) throws Exception {
		SSLContext clientSSLContext = SSLContext.getInstance("TLS");
		SSLContext serverSSLContext = SSLContext.getInstance("TLS");

		// Create self signed certificate
		TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("Rick");
		X509Certificate x509Cert = cert.getCertificate();

		// Create a SSLContext that uses that certificate
		SSLTestsUtils.initSSLContext(serverSSLContext, cert, null);

		// Or create a SSLContext that trusts this certificate
		SSLTestsUtils.initSSLContext(clientSSLContext, null, cert);
	}
}
