package com.github.benji.ssl.tests;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.github.benji.ssl.tests.utils.SSLTestsUtils;
import com.github.benji.ssl.tests.utils.TestCertificate;

import junit.framework.TestCase;

public class SSLClientServerTest extends TestCase {

	TestCertificate cert;
	CountDownLatch successResetLatch = new CountDownLatch(1);
	CountDownLatch exceptionResetLatch = new CountDownLatch(1);
	int serverPort;
	ServerSocket sslServerSocket;

	@Override
	protected void setUp() throws Exception {
		super.setUp();

		cert = SSLTestsUtils.createSelfSignedCertificate("TestServer");
		SSLContext serverSSLContext = SSLContext.getInstance("TLS");
		SSLTestsUtils.initSSLContext(serverSSLContext, cert);

		SSLServerSocketFactory serverSocketFactory = serverSSLContext.getServerSocketFactory();
		sslServerSocket = serverSocketFactory.createServerSocket(0);

		Thread thread = new Thread(() -> {
			while (true) {
				try {
					Socket client = sslServerSocket.accept();
					System.out.println("Accepted connection from " + client.getPort());
					BufferedReader r = new BufferedReader(new InputStreamReader(client.getInputStream()));
					String line = r.readLine();
					System.out.println("Received message: " + line);
					assertEquals("hello", line);
					successResetLatch.countDown();
					client.close();
				} catch (Throwable e) {
					exceptionResetLatch.countDown();
				}
			}
		});
		thread.start();
		serverPort = sslServerSocket.getLocalPort();
		System.out.println("Server started on port " + serverPort);
	}

	@Override
	protected void tearDown() throws Exception {
		sslServerSocket.close();
	}

	public void testSendMessageOnTrustedSocket() throws Exception {
		// creating SSL client
		SSLContext clientSSLContext = SSLContext.getInstance("TLS");
		SSLTestsUtils.initSSLContext(clientSSLContext, null, cert);
		SSLSocketFactory ssf = clientSSLContext.getSocketFactory();
		SSLSocket clientSslSocket = (SSLSocket) ssf.createSocket("localhost", serverPort);
		clientSslSocket.startHandshake();

		PrintWriter writer = new PrintWriter(new OutputStreamWriter(clientSslSocket.getOutputStream()));

		writer.println("hello");
		writer.flush();
		if (!successResetLatch.await(3, TimeUnit.SECONDS)) {
			fail("Server did not receive our message after 3 seconds.");
		}
	}

	public void testSendMessageOnUntrustedSocket() throws Exception {
		// Try failure scenario: when client doesn't trust server
		SSLContext clientSSLContext = SSLContext.getInstance("TLS");
		SSLTestsUtils.initSSLContext(clientSSLContext, null);
		SSLSocketFactory ssf = clientSSLContext.getSocketFactory();
		SSLSocket clientSslSocket = (SSLSocket) ssf.createSocket("localhost", serverPort);
		try {
			clientSslSocket.startHandshake();
			fail("Client should not have trusted the server.");
		} catch (Throwable th) {
			System.out.println("Handshake failed successfully.");
		}

		if (!exceptionResetLatch.await(3, TimeUnit.SECONDS)) {
			fail("Untrusted connection should have failed.");
		}
	}

}
