package com.github.benji.ssl.tests.utils.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.security.cert.X509CRL;

import com.github.benji.ssl.tests.utils.CRLTestsUtils;
import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

public class Example2 {
	public static void main(String[] args) throws Exception {
		File folder = new File("/tmp");

		// Create a Certificate Authority
		TestCertificate caCert = SSLTestsUtils.createSelfSignedCertificate("MyCustomCA");
		try (Writer writer = new FileWriter(new File(folder, "ca.pem"))) {
			SSLTestsUtils.writeCertificate(writer, caCert.getCertificate());
		}

		// Create a Certificate
		TestCertificate vdsCert = SSLTestsUtils.createSelfSignedCertificate("benji.github.com", caCert);
		vdsCert.setAlias("benji");
		vdsCert.setPassword("changeit");
		try (Writer writer = new FileWriter(new File(folder, "server1.pem"))) {
			SSLTestsUtils.writeCertificate(writer, vdsCert.getCertificate());
		}

		// Create a Key Store
		try (OutputStream out = new FileOutputStream(new File(folder, "my.keystore"))) {
			KeyStore ks = SSLTestsUtils.createKeyStore(vdsCert, "radiantlogic");
			ks.store(out, "radiantlogic".toCharArray());
		}

		// Create a CRL
		X509CRL crl = CRLTestsUtils.createCRL(caCert, vdsCert);
		try (Writer writer = new FileWriter(new File(folder, "crl.pem"))) {
			CRLTestsUtils.writeCRL(writer, crl);
		}
	}
}
