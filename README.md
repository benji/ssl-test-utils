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

Create self signed certificate:

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

Uses Bouncy Castle.
