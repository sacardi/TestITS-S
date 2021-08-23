package it.mascanc.its.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Map;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

/**
 * Simulates a receiving ITS-S, e.g., a OBE It receives a CAM (signed) and
 * validates it.
 * 
 * @author max
 *
 */
public class ReceivingITSS {

	private DefaultCryptoManager cryptoManager;
	private EtsiTs103097Certificate rootCACertificate;
	private EtsiTs103097Certificate authorityCACertificate;

	public ReceivingITSS() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		setupCryptoManager();
	}

	private void setupCryptoManager() throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
			BadCredentialsException, SignatureException {
		this.cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	}

	public String receive(byte[] encodedMessage)
			throws IllegalArgumentException, IOException, GeneralSecurityException {
		EtsiTs103097DataSigned camMessage = new EtsiTs103097DataSigned(encodedMessage);

		boolean signatureMatches = checkMessageSignature(camMessage);

		if (signatureMatches) {
			Logger.shortPrint("[receiving ITSS  ] 3) HOOORAY! Signature is valid! ");
		} else {
			throw new IllegalStateException("Signature validation failed");
		}

		return camMessage.getContent().getValue().toString();
	}

	private boolean checkMessageSignature(EtsiTs103097DataSigned camMessage)
			throws SignatureException, NoSuchAlgorithmException, IOException {
		ETSISecuredDataGenerator securedMessageGenerator = createSecuredMessageGenerator();

		// To decrypt and verify a signed message it is possible to use the following
		// First build a truststore of trust anchors (root CA certificate or equivalent)
		Map<HashedId8, Certificate> trustStore = securedMessageGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { rootCACertificate });
		// Second build a store of known certificate that might be referenced in the
		// message.

		Map<HashedId8, Certificate> certStore = securedMessageGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { authorityCACertificate });

		boolean back = securedMessageGenerator.verifySignedData(camMessage, certStore, trustStore);
		return back;
	}

	private ETSISecuredDataGenerator createSecuredMessageGenerator() throws SignatureException {
		ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(//
				ETSISecuredDataGenerator.DEFAULT_VERSION, //
				cryptoManager, //
				HashAlgorithm.sha256, //
				SignatureChoices.ecdsaNistP256Signature);
		return securedMessageGenerator;
	}

	public EtsiTs103097Certificate getAuthorityCACertificate() {
		return authorityCACertificate;
	}

	public void setAuthorityCACertificate(EtsiTs103097Certificate authorityCACertificate) {
		this.authorityCACertificate = authorityCACertificate;
	}

	public EtsiTs103097Certificate getRootCACertificate() {
		return rootCACertificate;
	}

	public void setRootCACertificate(EtsiTs103097Certificate rootCACertificate) {
		this.rootCACertificate = rootCACertificate;
	}

}
