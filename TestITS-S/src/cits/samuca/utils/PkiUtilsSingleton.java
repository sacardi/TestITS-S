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
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

public class PkiUtilsSingleton {

	private static PkiUtilsSingleton instance;

	private DefaultCryptoManager cryptoManager;
	private ETSIAuthorityCertGenerator authorityCertGenerator;
	private ETSITS102941MessagesCaGenerator messagesCaGenerator;
	private GeographicRegion geographicRegion;

	private PkiUtilsSingleton() {

		setCryptoManager();

		setAuthorityCertGenerator();

		setCaMessagesGenerator();

		setGeographicRegionToItaly();
	}

	private void setCryptoManager() {

		this.cryptoManager = new DefaultCryptoManager();

		try {
			this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

		} catch (IllegalArgumentException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| IOException | BadCredentialsException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void setAuthorityCertGenerator() {
		if (this.cryptoManager == null) {
			System.out.println("[PkiUtilsSingleton] Error: cryptoManager is null");
			System.exit(1);
		}

		try {
			this.authorityCertGenerator = new ETSIAuthorityCertGenerator(this.cryptoManager);

		} catch (SignatureException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void setCaMessagesGenerator() {
		if (this.cryptoManager == null) {
			System.out.println("[PkiUtilsSingleton] Error: cryptoManager is null");
			System.exit(1);
		}

		int versionToGenerate = Ieee1609Dot2Data.DEFAULT_VERSION;
		HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
		SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaNistP256Signature;

		try {
			this.messagesCaGenerator = new ETSITS102941MessagesCaGenerator( //
					versionToGenerate, //
					this.cryptoManager, //
					digestAlgorithm, //
					signatureScheme);

		} catch (SignatureException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void setGeographicRegionToItaly() {
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		this.geographicRegion = GeographicRegion.generateRegionForCountrys(countries);
	}

	public static PkiUtilsSingleton getInstance() {
		if (instance == null) {
			instance = new PkiUtilsSingleton();
		}
		return instance;
	}

	public DefaultCryptoManager getCryptoManager() {
		return this.cryptoManager;
	}

	public ETSIAuthorityCertGenerator getAuthorityCertGenerator() {
		return this.authorityCertGenerator;
	}

	public ETSITS102941MessagesCaGenerator getMessagesCaGenerator() {
		return messagesCaGenerator;
	}

	public GeographicRegion getGeographicRegion() {
		return this.geographicRegion;
	}

}
