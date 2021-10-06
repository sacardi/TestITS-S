package it.mascanc.its.security;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.AaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CrlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.DcEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.RootCaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedRcaCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;

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

	private static final String CtlCommands = null;

	private EtsiTs103097Certificate rootCaCertificate;

	private KeyPair rootCaSigningKeys;

	private KeyPair rootCaEncryptionKeys;

	private Ieee1609Dot2CryptoManager cryptoManager;

	private ETSIAuthorityCertGenerator authorityCertGenerator;

	private EtsiTs103097Certificate enrolmentCaCertificate;

	// Crypto stuff for the ENROLMENT CA
	private KeyPair enrollmentCaEncryptionKeys;

	private KeyPair enrollmentCaSigningKeys;

	private EtsiTs103097Certificate[] enrollmentCaChain;

	// Crypto stuff for the AUTHORIZATION CA
	private KeyPair authorizationCaEncryptionKeys;

	private KeyPair authorizationCaSigningKeys;

	private EtsiTs103097Certificate authorizationCaCertificate;

	private EtsiTs103097Certificate[] authorizationCAChain;

	private GeographicRegion geographicRegion;

	// Set the Root CA according with ETSI 103 097
	public RootCA() throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {

		init();

		createRootCACertificate();

		createEnrolmentCACertificate();

		createAuthorizationCACertificate();
	}

	public void run() {
		// not used
	}

	private void init() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException, InvalidKeyException {
		setupCryptoManager();

		setGeographicRegionToItaly();

		generateCertificateKeyPairs();
	}

	private void setupCryptoManager() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		// Create a crypto manager in charge of communicating with underlying
		// cryptographic components
		this.cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
		setAuthorityGenerator();
	}

	private void setAuthorityGenerator() throws SignatureException {
		// Create an authority certificate generator and initialize it with the crypto
		// manager.
		if (this.cryptoManager == null)
			throw new NullPointerException();
		this.authorityCertGenerator = new ETSIAuthorityCertGenerator(this.cryptoManager);
	}

	private void setGeographicRegionToItaly() {
		// this is defined in IEEE Std 1609. For italy we have:
		// https://www.iso.org/obp/ui/#iso:code:3166:IT

		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		this.geographicRegion = GeographicRegion.generateRegionForCountrys(countries);
	}

	private void generateCertificateKeyPairs() throws InvalidKeyException, IllegalArgumentException, IOException {
		// Root CA Keys
		this.rootCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		this.rootCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		// Enrollment CA Keys
		this.enrollmentCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		this.enrollmentCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		// Authorization CA Keys
		this.authorizationCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		this.authorizationCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
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
	 * (WHAT IT IS?) the issuer shall be set to sha256anddigest. The toBeSigned
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

		String cAName = "samuCA.autostrade.it";
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
		byte[] ctlServiceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries = Hex.decode("0138");
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signingPrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = rootCaEncryptionKeys.getPublic();

		this.rootCaCertificate = this.authorityCertGenerator.genRootCA(cAName, //
				rootCAValidityPeriod, //
//				this.geographicRegion, //
				null, // this is geographicRegion
				minChainDepth, //
				chainDepthRange, //
				ctlServiceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signingPrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey);

		Logger.shortPrint("[root CA         ] created Root CA certificate");
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

		String eAName = "EA.samuCA.autostrade.it";
		// This is a very long term certificate!!!!!
		ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 37);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.enrollmentCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.enrollmentCaEncryptionKeys.getPublic();

		// Generate a reference to the Enrollment CA Signing Keys
		this.enrolmentCaCertificate = this.authorityCertGenerator.genEnrollmentCA(eAName, //
				enrollmentCAValidityPeriod, //
				this.geographicRegion, //
//				subjectAssurance, //
				null, // subjectAssurance
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signerCertificate, //
				signerCertificatePublicKey, //
				signerCertificatePrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey //
		);
		this.enrollmentCaChain = new EtsiTs103097Certificate[] { this.enrolmentCaCertificate, this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] created Enrolment CA certificate");
	}

	private void createAuthorizationCACertificate() throws IllegalArgumentException, SignatureException, IOException {

		String aAName = "AA.samuCA.autostrade.it";
		ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 15);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.authorizationCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.authorizationCaEncryptionKeys.getPublic();

		// Generate a reference to the Authorization CA Signing Keys
		this.authorizationCaCertificate = this.authorityCertGenerator.genAuthorizationCA(aAName, //
				authorityCAValidityPeriod, //
				this.geographicRegion, //
//				subjectAssurance, //
				null, // subjectAssurance
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signerCertificate, //
				signerCertificatePublicKey, //
				signerCertificatePrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey //
		);
		this.authorizationCAChain = new EtsiTs103097Certificate[] { this.authorizationCaCertificate,
				this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] created Authorization CA certificate");
	}

	public EtsiTs103097Certificate getRootCaCertificate() {
		return this.rootCaCertificate;
	}

	public KeyPair getEnrollmentCaEncryptionKeys() {
		return enrollmentCaEncryptionKeys;
	}

	public void setEnrollmentCAEncryptionKeys(KeyPair enrollmentCAEncryptionKeys) {
		this.enrollmentCaEncryptionKeys = enrollmentCAEncryptionKeys;
	}

	public EtsiTs103097Certificate getMyCertificate() {
		return rootCaCertificate;
	}

	public void setMyCertificate(EtsiTs103097Certificate myCertificate) {
		this.rootCaCertificate = myCertificate;
	}

	public KeyPair getRootCASigningKeys() {
		return rootCaSigningKeys;
	}

	public void setRootCASigningKeys(KeyPair rootCASigningKeys) {
		this.rootCaSigningKeys = rootCASigningKeys;
	}

	public KeyPair getRootCAEncryptionKeys() {
		return rootCaEncryptionKeys;
	}

	public void setRootCAEncryptionKeys(KeyPair rootCAEncryptionKeys) {
		this.rootCaEncryptionKeys = rootCAEncryptionKeys;
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

	public KeyPair getEnrollmentCaSigningKeys() {
		return enrollmentCaSigningKeys;
	}

	public void setEnrollmentCASigningKeys(KeyPair enrollmentCASigningKeys) {
		this.enrollmentCaSigningKeys = enrollmentCASigningKeys;
	}

	public EtsiTs103097Certificate getEnrollmentCaCertificate() {
		return enrolmentCaCertificate;
	}

	public void setEnrollmentCACertificate(EtsiTs103097Certificate enrollmentCACertificate) {
		this.enrolmentCaCertificate = enrollmentCACertificate;
	}

	public EtsiTs103097Certificate[] getEnrollmentCaChain() {
		return enrollmentCaChain;
	}

	public void setEnrollmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
		this.enrollmentCaChain = enrollmentCAChain;
	}

	public static int getPort() {
		return port;
	}

	public KeyPair getAuthorizationCaEncryptionKeys() {
		return authorizationCaEncryptionKeys;
	}

	public void setAuthorizationCAEncryptionKeys(KeyPair authorizationCAEncryptionKeys) {
		this.authorizationCaEncryptionKeys = authorizationCAEncryptionKeys;
	}

	public KeyPair getAuthorizationCaSigningKeys() {
		return authorizationCaSigningKeys;
	}

	public void setAuthorizationCASigningKeys(KeyPair authorizationCASigningKeys) {
		this.authorizationCaSigningKeys = authorizationCASigningKeys;
	}

	public EtsiTs103097Certificate getAuthorizationCaCertificate() {
		return authorizationCaCertificate;
	}

	public void setAuthorizationCACertificate(EtsiTs103097Certificate authorizationCACertificate) {
		this.authorizationCaCertificate = authorizationCACertificate;
	}

	public EtsiTs103097Certificate[] getAuthorizationCaChain() {
		return authorizationCAChain;
	}

	public void setAuthorizationCAChain(EtsiTs103097Certificate[] authorizationCAChain) {
		this.authorizationCAChain = authorizationCAChain;
	}

	private ETSITS102941MessagesCaGenerator messagesCaGenerator = null;

	private void setCaMessagesGenerator() throws SignatureException {
		if (this.messagesCaGenerator != null) {
			return;
		}
		int versionToGenerate = Ieee1609Dot2Data.DEFAULT_VERSION;
		HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
		SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaNistP256Signature;

		this.messagesCaGenerator = new ETSITS102941MessagesCaGenerator( //
				versionToGenerate, //
				this.cryptoManager, //
				digestAlgorithm, //
				signatureScheme);
	}

	static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

	private ToBeSignedRcaCtl generateCtlRequest() throws Exception {
		final Version version = Version.V1;
		final Time32 nextUpdate = new Time32(dateFormat.parse("20250910 14:14:14"));
		final boolean isFullCtl = true;
		final int ctlSequence = 1;

		// for pvendil: according to the standard
		// TODO: parameter linkRootCaCertificate of RootCaEntry must be optional
		// TODO: parameter itsAccessPoint of EaEntry must be optional
		// TODO: parameter accessPoint of AaEntry must be optional
		final Url itsAccessPoint = new Url("http://localhost/dummy/itss");
		final Url eaAccessPoint = new Url("http://localhost/dummy/ea");
		final Url aaAccessPoint = new Url("http://localhost/dummy/aa");
		final Url dcAccessPoint = new Url("http://localhost/dummy/dc");

		// IMPORTANT: as per ETSI TS 102 941 v1.3.1, ToBeSignedRcaCtl cannot contain ctl
		// commands for add [rca, tlm]
		
		
		
		
//		HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"));
//		this.authorityCertGenerator.gen
//		
		
		HashedId8[] certificateDigests = {new HashedId8(this.rootCaCertificate.getEncoded())};
				
		final CtlCommand[] ctlCommands = new CtlCommand[] { //
//				new CtlCommand(new CtlEntry(new RootCaEntry(this.rootCaCertificate, rootCaCertificate))), // WRONG
				new CtlCommand(new CtlEntry(new EaEntry(this.enrolmentCaCertificate, eaAccessPoint, itsAccessPoint))), //
				new CtlCommand(new CtlEntry(new AaEntry(this.authorizationCaCertificate, aaAccessPoint))), //
				new CtlCommand(new CtlEntry(new DcEntry(dcAccessPoint, new SequenceOfHashedId8(certificateDigests)))), //
		};

		return new ToBeSignedRcaCtl( //
				version, //
				nextUpdate, //
				isFullCtl, //
				ctlSequence, //
				ctlCommands);
	}

	/**
	 * Help method that generated a HashedId8 cert id from a certificate.
	 */
	public HashedId8 getCertID(Certificate cert)
			throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		HashAlgorithm hashAlgorithm = HashAlgorithm.sha256;
		if (cert.getType() == CertificateType.explicit) {
			VerificationKeyIndicator vki = cert.getToBeSigned().getVerifyKeyIndicator();
			PublicVerificationKey pvk = (PublicVerificationKey) vki.getValue();
			if (pvk.getValue() instanceof EccP384CurvePoint) {
				hashAlgorithm = HashAlgorithm.sha384;
			}
		}

		return new HashedId8(cryptoManager.digest(cert.getEncoded(), hashAlgorithm));
	}

	public void generateCTL() throws Exception {
		// First generate to be signed data
		// EtsiTs103097DataSigned CTL =
		// this.messagesCaGenerator.genRcaCertificateTrustListMessage( , null,
		// authorizationCAChain, null)

		ToBeSignedRcaCtl toBeSignedCtl = generateCtlRequest();

		setCaMessagesGenerator();
		final Time64 signingGenerationTime = new Time64(new Date());
		System.out.println(signingGenerationTime);
		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.rootCaCertificate };

		final PrivateKey signerPrivateKey = this.rootCaSigningKeys.getPrivate(); // correct

		EtsiTs103097DataSigned certificateTrustListMessage = this.messagesCaGenerator.genRcaCertificateTrustListMessage(//
				signingGenerationTime, //
				toBeSignedCtl, //
				signerCertificateChain, //
				signerPrivateKey);

//		System.out.println("rootCA: " + getCertID(this.rootCaCertificate));
//		System.out.println("EA: " + getCertID(this.enrolmentCaCertificate));
//		System.out.println("AA: " + getCertID(this.authorizationCaCertificate));

		Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[] {
				this.rootCaCertificate, this.enrolmentCaCertificate, this.authorizationCaCertificate });

		// To verify CTL and CRL messages
		Map<HashedId8, Certificate> ctlTrustStore = new HashMap<>(); // Only root ca needed from truststore in this
																		// case. TODO: understand why (but it works)
		ctlTrustStore.put(getCertID(this.rootCaCertificate), this.rootCaCertificate);

//		VerifyResult<ToBeSignedRcaCtl> crlVerifyResult = this.messagesCaGenerator
//				.verifyRcaCertificateTrustListMessage(certificateTrustListMessage, trustStore, ctlTrustStore);

		// write CTL to file
		writeCtlToFile(certificateTrustListMessage, "CTL.coer");
//		System.out.println(certificateTrustListMessage);

//		writeInnerCtlToFile(toBeSignedCtl, "innerCTL.coer");
//		System.out.println(toBeSignedCtl);
//		write102941DataCtlToFile(new EtsiTs102941Data(Version.V1_1_1, new EtsiTs102941DataContent(toBeSignedCtl)),
//				"CTL102941Data.coer");
//		System.out.println(new EtsiTs102941Data(Version.V1, new EtsiTs102941DataContent(toBeSignedCtl)));
//		write102941DataContentCtlToFile(new EtsiTs102941DataContent(toBeSignedCtl), "CTL102941DataContent.coer");

		writeCertificateToFile(this.rootCaCertificate, "RootCA.coer");
		writeCertificateToFile(this.enrolmentCaCertificate, "EnrolmentCA.coer");
		writeCertificateToFile(this.authorizationCaCertificate, "AuthorizationCA.coer");
	}

	private void write102941DataCtlToFile(EtsiTs102941Data certificateTrustListMessage, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		certificateTrustListMessage.encode(dataOutputStream);
		dataOutputStream.close();
	}

//	private void write102941DataContentCtlToFile(EtsiTs102941DataContent certificateTrustListMessage, String filename)
//			throws FileNotFoundException, IOException {
//		DataOutputStream dataOutputStream = new DataOutputStream(
//                new FileOutputStream(filename));
//		certificateTrustListMessage.encode(dataOutputStream);
//		dataOutputStream.close();
//	}

	private void writeInnerCtlToFile(ToBeSignedRcaCtl innerCertificateTrustListMessage, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		innerCertificateTrustListMessage.encode(dataOutputStream);
		dataOutputStream.close();
	}

	private void writeCtlToFile(EtsiTs103097DataSigned certificateTrustListMessage, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		certificateTrustListMessage.encode(dataOutputStream);
		dataOutputStream.close();
	}

	private void writeCertificateToFile(EtsiTs103097Certificate certificate, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		certificate.encode(dataOutputStream);
		dataOutputStream.close();
	}

	public void readCTL(String filename) throws Exception {
		// read CTL from file
		setCaMessagesGenerator();

		DataInputStream dataInputStream = new DataInputStream(new FileInputStream(filename));
		EtsiTs103097DataSigned certificateTrustListMessage = new EtsiTs103097DataSigned();
		certificateTrustListMessage.decode(dataInputStream);
		dataInputStream.close();

		Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[] {
				this.rootCaCertificate, this.enrolmentCaCertificate, this.authorizationCaCertificate });

		// To verify CTL and CRL messages
		Map<HashedId8, Certificate> ctlTrustStore = new HashMap<>(); // Only root ca needed from truststore in this
																		// case. TODO: understand why (but it works)
		ctlTrustStore.put(getCertID(this.rootCaCertificate), this.rootCaCertificate);

//		System.out.println("rootCA: " + getCertID(this.rootCaCertificate));
//		System.out.println("EA: " + getCertID(this.enrolmentCaCertificate));
//		System.out.println("AA: " + getCertID(this.authorizationCaCertificate));

//		VerifyResult<ToBeSignedRcaCtl> crlVerifyResult = this.messagesCaGenerator
//				.verifyRcaCertificateTrustListMessage(certificateTrustListMessage, trustStore, ctlTrustStore);
//		System.out.println("Everything is OK.");
	}

	public void readCTL_cohda(String filename) throws Exception {
		// read CTL from file
		setCaMessagesGenerator();

		DataInputStream dataInputStream = new DataInputStream(new FileInputStream(filename));
		EtsiTs103097DataSigned certificateTrustListMessage = new EtsiTs103097DataSigned();
		certificateTrustListMessage.decode(dataInputStream);
		dataInputStream.close();

		Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[] {
				this.rootCaCertificate, this.enrolmentCaCertificate, this.authorizationCaCertificate });

		// To verify CTL and CRL messages
		Map<HashedId8, Certificate> ctlTrustStore = new HashMap<>(); // Only root ca needed from truststore in this
																		// case. TODO: understand why (but it works)
		ctlTrustStore.put(getCertID(this.rootCaCertificate), this.rootCaCertificate);

//		System.out.println("rootCA: " + getCertID(this.rootCaCertificate));
//		System.out.println("EA: " + getCertID(this.enrolmentCaCertificate));
//		System.out.println("AA: " + getCertID(this.authorizationCaCertificate));

		System.out.println(certificateTrustListMessage);
		writeCtlToFile(certificateTrustListMessage, "ctl_cohda_rewrite.coer");

//		VerifyResult<ToBeSignedRcaCtl> crlVerifyResult = this.messagesCaGenerator
//				.verifyRcaCertificateTrustListMessage(certificateTrustListMessage, trustStore, ctlTrustStore);
//		System.out.println("Everything is OK.");
	}
}
