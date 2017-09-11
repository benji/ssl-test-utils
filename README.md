# ssl-test-utils
Creates self signed certificates / keystores / truststores / SSLContexts for testing

 
```
<repository>
  <id>jitpack.io</id>
  <url>https://jitpack.io</url>
</repository>
```

```
<dependency>
  <groupId>com.github.benji</groupId>
  <artifactId>ssl-test-utils</artifactId>
  <version>1.0.0</version>
</dependency>
```

Example 1:
```
// Create self signed certificate
TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("Rick");
X509Certificate x509Cert = cert.getCertificate();

// Create a SSLContext that uses that certificate
SSLTestsUtils.initSSLContext(serverSSLContext, cert, null);

// Or create a SSLContext that trusts this certificate
SSLTestsUtils.initSSLContext(clientSSLContext, null, cert);
```

Example 2:

```
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
```

Uses Bouncy Castle.
