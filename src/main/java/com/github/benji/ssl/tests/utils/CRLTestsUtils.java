package com.github.benji.ssl.tests.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CRLTestsUtils {

	public static X509CRLHolder createCRLHolder(TestCertificate caCert, TestCertificate cert)
			throws OperatorCreationException, CRLException {
		Date now = new Date();
		X500Name issuer = SSLTestsUtils.getX500Name(caCert.getName());
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuer, now);

		Calendar tomorrowCal = Calendar.getInstance();
		tomorrowCal.setTime(now);
		tomorrowCal.add(Calendar.DATE, 1);

		crlGen.setNextUpdate(tomorrowCal.getTime());

		crlGen.addCRLEntry(cert.getCertificate().getSerialNumber(), now, CRLReason.privilegeWithdrawn);

		ContentSigner sigGen = new JcaContentSignerBuilder(SSLTestsUtils.SignatureAlgorithm)
				.setProvider(SSLTestsUtils.Provider).build(caCert.getPrivateKey());
		return crlGen.build(sigGen);
	}

	public static X509CRL createCRL(TestCertificate caCert, TestCertificate cert)
			throws OperatorCreationException, CRLException {
		JcaX509CRLConverter converter = new JcaX509CRLConverter();
		converter.setProvider(SSLTestsUtils.Provider);
		return converter.getCRL(createCRLHolder(caCert, cert));
	}

	public static void initTrustManagerWithCRLs(TrustManagerFactory tmf, KeyStore trustStore, CRL... crls)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException {
		String algorithm = tmf.getAlgorithm();

		if (!algorithm.equalsIgnoreCase("PKIX")) {
			System.err.println("CRL not supported for this algorithm: " + algorithm);
			tmf.init(trustStore);
			return;
		}

		X509CertSelector targetConstraints = new X509CertSelector();
		PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, targetConstraints);

		if (crls != null) {
			CertStoreParameters csp = new CollectionCertStoreParameters(Arrays.asList(crls));
			CertStore crl_store = CertStore.getInstance("Collection", csp);
			pkixParams.addCertStore(crl_store);
		}

		pkixParams.setRevocationEnabled(true);
		ManagerFactoryParameters trustParams = new CertPathTrustManagerParameters(pkixParams);

		tmf.init(trustParams);
	}

	public static CRL[] loadCRL(InputStream in) throws CertificateException, CRLException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Collection<? extends CRL> crls = cf.generateCRLs(in);
		return crls.toArray(new CRL[crls.size()]);
	}

	public static void writeCRL(OutputStream out, X509CRL crl) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		OutputStreamWriter oswriter = new OutputStreamWriter(byteArrayOutputStream);
		JcaPEMWriter writer = new JcaPEMWriter(oswriter);
		writer.writeObject(crl);
		writer.close();
		byte[] data = byteArrayOutputStream.toByteArray();
		out.write(data);
	}
}
