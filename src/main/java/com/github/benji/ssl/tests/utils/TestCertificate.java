package com.github.benji.ssl.tests.utils;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TestCertificate {

	private String name;
	private String password;
	private String alias;
	private X509Certificate certificate;
	private PrivateKey privateKey;

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public String getName() {
		return name;
	}

	public String getAlias() {
		return alias != null ? alias : name;
	}

	public String getPassword() {
		return password != null ? password : name;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

}
