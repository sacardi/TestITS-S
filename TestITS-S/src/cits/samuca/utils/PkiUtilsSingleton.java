package cits.samuca.utils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;

public class PkiUtilsSingleton {

	private static PkiUtilsSingleton instance;
	private DefaultCryptoManager cryptoManager;
	private ETSIAuthorityCertGenerator authorityCertGenerator;
	private GeographicRegion geographicRegion;

	private PkiUtilsSingleton() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {

		setupCryptoManager();

		setGeographicRegionToItaly();
	}

	private void setupCryptoManager() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		this.cryptoManager = new DefaultCryptoManager();
		this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
		setAuthorityGenerator();
	}

	private void setAuthorityGenerator() throws SignatureException {
		if (this.cryptoManager == null)
			throw new NullPointerException();
		this.authorityCertGenerator = new ETSIAuthorityCertGenerator(this.cryptoManager);
	}

	private void setGeographicRegionToItaly() {
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		this.geographicRegion = GeographicRegion.generateRegionForCountrys(countries);
	}

	public static PkiUtilsSingleton getInstance() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		if (instance == null) {
			instance = new PkiUtilsSingleton();
		}
		return instance;
	}

	public ETSIAuthorityCertGenerator getAuthorityCertGenerator() {
		return this.authorityCertGenerator;
	}

	public DefaultCryptoManager getCryptoManager() {
		return this.cryptoManager;
	}

	public GeographicRegion getGeographicRegion() {
		return this.geographicRegion;
	}
}
