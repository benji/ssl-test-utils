package com.github.benji.ssl.tests;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

import junit.framework.TestCase;

public class ReadWriteTest extends TestCase {

	public void testReadWriteCertificate() throws Exception {
		TestCertificate testCert = SSLTestsUtils.createSelfSignedCertificate("onepunch");

		StringWriter writer = new StringWriter();
		SSLTestsUtils.writeCertificate(writer, testCert.getCertificate());

		StringReader reader = new StringReader(writer.toString());
		X509Certificate outCert = SSLTestsUtils.readCertificate(reader);

		assertEquals(testCert.getCertificate(), outCert);
	}

}
