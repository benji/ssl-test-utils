# ssl-test-utils
Creates self signed certificates / keystores / truststores / SSLContexts for testing

Uses Bouncy Castle

Create self signed::
```
TestCertificate cert = SSLTestsUtils.createSelfSignedCertificate("Rick");
X509Certificate x509Cert = cert.getCertificate();
```

Create a SSLContext that trusts this certificate:
```SSLContext sslContext = SSLContext.getInstance("TLS");
SSLTestsUtils.initSSLContext(sslContext, null, cert);
```

Create a SSLContext that uses that certificate:
```SSLContext sslContext = SSLContext.getInstance("TLS");
SSLTestsUtils.initSSLContext(sslContext, cert, null);
```
