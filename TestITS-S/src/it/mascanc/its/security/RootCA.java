package it.mascanc.its.security;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;

/**
 * This is the root CA mock. It starts a server listening on port 8886. The
 * reference standard is <a href=
 * "https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.03.01_60/ts_103097v010301p.pdf">Here</a>
 * 
 * It is defined in 102 940 as the The Root CA is the highest level CA in the
 * certification hierarchy. It provides EA and AA with proof that it may issue
 * respectively enrolment credentials, authorization tickets
 * 
 * @author max
 *
 */
public class RootCA implements Runnable {
	public static final int port = 8886;

	private EtsiTs103097Certificate rootCACertificate;

	private KeyPair rootCASigningKeys;

	private KeyPair rootCAEncryptionKeys;

	private Ieee1609Dot2CryptoManager cryptoManager;

	private ETSIAuthorityCertGenerator authorityCertGenerator;

	private EtsiTs103097Certificate enrolmentCaCertificate;

	// Crypto stuff for the ENROLMENT CA
	private KeyPair enrollmentCAEncryptionKeys;

	private KeyPair enrollmentCASigningKeys;

	private EtsiTs103097Certificate enrollmentCACertificate;

	private EtsiTs103097Certificate[] enrollmentCAChain;

	// Crypto stuff for the AUTHORIZATION CA
	private KeyPair authorizationCAEncryptionKeys;

	private KeyPair authorizationCASigningKeys;

	private EtsiTs103097Certificate authorizationCACertificate;

	private EtsiTs103097Certificate[] authorizationCAChain;

	private GeographicRegion geographicRegion;

	// Set the Root CA according with ETSI 103 097
	public RootCA() throws IllegalArgumentException, SignatureException, IOException {

		init();

		createRootCACertificate();

		createEnrolmentCACertificate();

		createAuthorizationCACertificate();
	}

	public void run() {
		// not used
	}

	private void init() {
		setupCryptoManager();

		setRegionToItaly();

		generateCertificateKeyPairs();
	}

	private void setupCryptoManager() {
		// Create a crypto manager in charge of communicating with underlying
		// cryptographic components
		this.cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		try {
			this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
		} catch (Exception e) {
			System.out.println("Exception with setupCryptoManager: " + e);
		}

		setAuthorityGenerator();
	}

	private void setAuthorityGenerator() {
		try {
			// Create an authority certificate generator and initialize it with the crypto
			// manager.
			this.authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);
		} catch (SignatureException e) {
			System.out.println("Exception with setupCryptoManager: " + e);
		}
	}

	private void setRegionToItaly() {
		// this is defined in IEEE Std 1609. For italy we have:
		// https://www.iso.org/obp/ui/#iso:code:3166:IT

		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		this.geographicRegion = GeographicRegion.generateRegionForCountrys(countries);
	}

	private void generateCertificateKeyPairs() {
		try {
			// Root CA Keys
			this.rootCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
			this.rootCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

			// Enrollment CA Keys
			this.enrollmentCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
			this.enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

			// CA Keys
			this.authorizationCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
			this.authorizationCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		} catch (Exception e) {
			System.out.println("Exception with generateKeyPairs: " + e);
		}
	}

	/**
	 * Something to say: according with ETSI, the data structures are in ASN.1
	 * encoded using COER, the Canonical Octect Encoding Rules (sic!). The data
	 * structure is of type Ieee1609Dot2Data (the reason of the crypto manager). The
	 * idea is that the data structure EtsiTs103097Data is the same as iee.
	 * 
	 * A certificate contains signedData, encryptedData, and unsecuredData
	 * 
	 * The definition of the root CA is defined in clause 7.2.3.
	 * 
	 * For the root ca, the issuer shall be self. But for authority link certificate
	 * (WHAT IT IS?) the issuer shalol be set to sha256anddigest. The toBeSigned
	 * data shall contain the certIssuePermissions shall contain the permissions to
	 * sign subordinate certification authorities. The appPermissions shall be used
	 * to indicate permissions to sign: CRLs and contains the ITS AID for the CRL as
	 * assigned in ETSI TS 102 965 CTL.
	 * 
	 * In ETSI TS 102 965
	 * https://www.etsi.org/deliver/etsi_ts/102900_102999/102965/01.03.01_60/ts_102965v010301p.pdf,
	 * si parla di AID, Application Object Identifier. However the technical issues
	 * of GUIA, it is defined in CEN/ISO TS 17419:2018, which is based on the ITS
	 * station as specified in ISO 21217:2014 (strasic!)
	 * 
	 * @return
	 * @throws IOException
	 * @throws SignatureExceptio
	 * @throws IllegalArgumentExceptio
	 */
	public void createRootCACertificate() throws IllegalArgumentException, SignatureException, IOException {

		String cAName = "testrootca.autostrade.it";
		// Defined in section 6.
		ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);
		int minChainDepth = 3;
		int chainDepthRange = -1;
		// What I don't know: the minChainDepth and the chainDepthRange. The EC is
		// mandated by the standard. The CTL is the Certificate Trust List, I don't know
		// what is the 0138.
		// From ETSI TS 102 941 v1.3.1, section B.2:
		// 01 -> (SSP version control) version 01
		// 38 -> (Service-specific parameters) 0x38 == 0b 0011 1000
		// - 0 The certificate CANNOT be used to sign CTL containing the TLM entries
		// - 0 The certificate CANNOT be used to sign CTL containing the Root CA entries
		// - 1 The certificate CAN be used to sign CTL containing the EA entries
		// - 1 The certificate CAN be used to sign CTL containing the AA entries
		// - 1 The certificate CAN be used to sign CTL containing the DC entries
		// - 0 unused
		// - 0 unused
		// - 0 unused
		byte[] cTLServiceSpecificPermissions_canSignCTLwith_EA_AA_DC = Hex.decode("0138");
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = rootCASigningKeys.getPublic();
		PrivateKey signingPrivateKey = rootCASigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = rootCAEncryptionKeys.getPublic();

		rootCACertificate = authorityCertGenerator.genRootCA(cAName, //
				rootCAValidityPeriod, //
				this.geographicRegion, //
				minChainDepth, //
				chainDepthRange, //
				cTLServiceSpecificPermissions_canSignCTLwith_EA_AA_DC, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signingPrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey);

		System.out.println("Created Root CA certificate");
	}

	/**
	 * Here I create the certificate of the enrolment CA, which is giving the
	 * certificates to all of the ITS stations.
	 * 
	 * @return
	 * @throws IllegalArgumentException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	private void createEnrolmentCACertificate() throws IllegalArgumentException, SignatureException, IOException {

		String eAName = "testea.autostrade.it";
		// This is a very long term certificate!!!!!
		ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 37);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = enrollmentCASigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCACertificate;
		PublicKey signerCertificatePublicKey = rootCASigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = rootCASigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = enrollmentCAEncryptionKeys.getPublic();

		// Generate a reference to the Enrollment CA Signing Keys
		enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA(eAName, //
				enrollmentCAValidityPeriod, //
				this.geographicRegion, //
				subjectAssurance, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signerCertificate, //
				signerCertificatePublicKey, //
				signerCertificatePrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey //
		);
		this.enrollmentCAChain = new EtsiTs103097Certificate[] { enrollmentCACertificate, rootCACertificate };

		System.out.println("Created Enrolment CA certificate");
	}

	private void createAuthorizationCACertificate() throws IllegalArgumentException, SignatureException, IOException {

		String aAName = "testaa.autostrade.it";
		ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 15);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = authorizationCASigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCACertificate;
		PublicKey signerCertificatePublicKey = rootCASigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = rootCASigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = authorizationCAEncryptionKeys.getPublic();

		// Generate a reference to the Authorization CA Signing Keys
		authorizationCACertificate = authorityCertGenerator.genAuthorizationCA(aAName, //
				authorityCAValidityPeriod, //
				geographicRegion, //
				subjectAssurance, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signerCertificate, //
				signerCertificatePublicKey, //
				signerCertificatePrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey //
		);
		this.authorizationCAChain = new EtsiTs103097Certificate[] { authorizationCACertificate, rootCACertificate };

		System.out.println("Created Authorization CA certificate");
	}

	public EtsiTs103097Certificate getRootCACertificate() {
		return this.rootCACertificate;
	}

	public KeyPair getEnrollmentCAEncryptionKeys() {
		return enrollmentCAEncryptionKeys;
	}

	public void setEnrollmentCAEncryptionKeys(KeyPair enrollmentCAEncryptionKeys) {
		this.enrollmentCAEncryptionKeys = enrollmentCAEncryptionKeys;
	}

	public EtsiTs103097Certificate getMyCertificate() {
		return rootCACertificate;
	}

	public void setMyCertificate(EtsiTs103097Certificate myCertificate) {
		this.rootCACertificate = myCertificate;
	}

	public KeyPair getRootCASigningKeys() {
		return rootCASigningKeys;
	}

	public void setRootCASigningKeys(KeyPair rootCASigningKeys) {
		this.rootCASigningKeys = rootCASigningKeys;
	}

	public KeyPair getRootCAEncryptionKeys() {
		return rootCAEncryptionKeys;
	}

	public void setRootCAEncryptionKeys(KeyPair rootCAEncryptionKeys) {
		this.rootCAEncryptionKeys = rootCAEncryptionKeys;
	}

	public Ieee1609Dot2CryptoManager getCryptoManager() {
		return cryptoManager;
	}

	public void setCryptoManager(Ieee1609Dot2CryptoManager cryptoManager) {
		this.cryptoManager = cryptoManager;
	}

	public EtsiTs103097Certificate getEnrolmentCaCertificate() {
		return enrolmentCaCertificate;
	}

	public void setEnrolmentCaCertificate(EtsiTs103097Certificate enrolmentCaCertificate) {
		this.enrolmentCaCertificate = enrolmentCaCertificate;
	}

	public KeyPair getEnrollmentCASigningKeys() {
		return enrollmentCASigningKeys;
	}

	public void setEnrollmentCASigningKeys(KeyPair enrollmentCASigningKeys) {
		this.enrollmentCASigningKeys = enrollmentCASigningKeys;
	}

	public EtsiTs103097Certificate getEnrollmentCACertificate() {
		return enrollmentCACertificate;
	}

	public void setEnrollmentCACertificate(EtsiTs103097Certificate enrollmentCACertificate) {
		this.enrollmentCACertificate = enrollmentCACertificate;
	}

	public EtsiTs103097Certificate[] getEnrollmentCAChain() {
		return enrollmentCAChain;
	}

	public void setEnrollmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
		this.enrollmentCAChain = enrollmentCAChain;
	}

	public static int getPort() {
		return port;
	}

	public KeyPair getAuthorizationCAEncryptionKeys() {
		return authorizationCAEncryptionKeys;
	}

	public void setAuthorizationCAEncryptionKeys(KeyPair authorizationCAEncryptionKeys) {
		this.authorizationCAEncryptionKeys = authorizationCAEncryptionKeys;
	}

	public KeyPair getAuthorizationCASigningKeys() {
		return authorizationCASigningKeys;
	}

	public void setAuthorizationCASigningKeys(KeyPair authorizationCASigningKeys) {
		this.authorizationCASigningKeys = authorizationCASigningKeys;
	}

	public EtsiTs103097Certificate getAuthorizationCACertificate() {
		return authorizationCACertificate;
	}

	public void setAuthorizationCACertificate(EtsiTs103097Certificate authorizationCACertificate) {
		this.authorizationCACertificate = authorizationCACertificate;
	}

	public EtsiTs103097Certificate[] getAuthorizationCAChain() {
		return authorizationCAChain;
	}

	public void setAuthorizationCAChain(EtsiTs103097Certificate[] authorizationCAChain) {
		this.authorizationCAChain = authorizationCAChain;
	}

}
