package cits.pki;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
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
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.AaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.DcEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedRcaCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
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

public class RootCA {
	public static final int port = 8886;

	private Ieee1609Dot2CryptoManager cryptoManager;

	private GeographicRegion geographicRegion;

	private ETSIAuthorityCertGenerator authorityCertGenerator;

	private ETSITS102941MessagesCaGenerator messagesCaGenerator = null;

	// Crypto stuff for the ROOT CA
	private EtsiTs103097Certificate rootCaCertificate;

	private KeyPair rootCaSigningKeys;

	private KeyPair rootCaEncryptionKeys;

	// Crypto stuff for the ENROLMENT CA
	private EtsiTs103097Certificate enrolmentCaCertificate;

	private KeyPair enrolmentCaEncryptionKeys;

	private KeyPair enrolmentCaSigningKeys;

	private EtsiTs103097Certificate[] enrolmentCaChain;

	// Crypto stuff for the AUTHORIZATION CA
	private KeyPair authorizationCaEncryptionKeys;

	private KeyPair authorizationCaSigningKeys;

	private EtsiTs103097Certificate authorizationCaCertificate;

	private EtsiTs103097Certificate[] authorizationCAChain;

	public RootCA() throws Exception {
		init();

		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readRootCaCertificateAndKeyPairs();

			readEnrolmentCaCertificateAndKeyPairs();

			readAuthorizationCaCertificateAndKeyPairs();
		} else {
			createRootCaCertificateAndKeyPairs();

			createEnrolmentCaCertificateAndKeyPairs();

			createAuthorizationCaCertificateAndKeyPairs();
		}
		
		generateCTL();
	}

	private void init() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException, InvalidKeyException {
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

	public void createRootCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException {

		this.rootCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.rootCaSigningKeys.getPrivate(), Constants.ROOT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.rootCaSigningKeys.getPublic(), Constants.ROOT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.rootCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.rootCaEncryptionKeys.getPrivate(), Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.rootCaEncryptionKeys.getPublic(), Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		String caName = "samuCA.autostrade.it";
		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000);
		ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 45);
		int minChainDepth = 3;
		int chainDepthRange = -1;

		byte[] ctlServiceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries = Hex.decode("0138");
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signingPrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = rootCaEncryptionKeys.getPublic();

		this.rootCaCertificate = this.authorityCertGenerator.genRootCA(//
				caName, //
				rootCAValidityPeriod, //
				this.geographicRegion, //
				minChainDepth, //
				chainDepthRange, //
				ctlServiceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signingPrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey);

		writeCertificateToFile(this.rootCaCertificate, Constants.ROOT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Root CA certificate written to file");
	}

	public void readRootCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException, ClassNotFoundException {

		PrivateKey privateSigningKey = readPrivateKeyFromFile(Constants.ROOT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = readPublicKeyFromFile(Constants.ROOT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.rootCaSigningKeys = new KeyPair(publicSigningKey, privateSigningKey);

		PrivateKey privateEncryptionKey = readPrivateKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = readPublicKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.rootCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);

		this.rootCaCertificate = readCertificateFromFile(Constants.ROOT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Root CA certificate read from file");
	}

	private void createEnrolmentCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException {

		this.enrolmentCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.enrolmentCaSigningKeys.getPrivate(), Constants.ENROLMENT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.enrolmentCaSigningKeys.getPublic(), Constants.ENROLMENT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.enrolmentCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.enrolmentCaEncryptionKeys.getPrivate(),
				Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.enrolmentCaEncryptionKeys.getPublic(),
				Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		String eAName = "EA.samuCA.autostrade.it";
		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000);
		ValidityPeriod enrolmentCAValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 37);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.enrolmentCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.enrolmentCaEncryptionKeys.getPublic();

		this.enrolmentCaCertificate = this.authorityCertGenerator.genEnrollmentCA(eAName, //
				enrolmentCAValidityPeriod, //
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
		this.enrolmentCaChain = new EtsiTs103097Certificate[] { this.enrolmentCaCertificate, this.rootCaCertificate };

		writeCertificateToFile(this.enrolmentCaCertificate, Constants.ENROLMENT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Enrolment CA certificate written to file");
	}
	
	private void readEnrolmentCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException, ClassNotFoundException {

		PrivateKey privateSigningKey = readPrivateKeyFromFile(Constants.ENROLMENT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = readPublicKeyFromFile(Constants.ENROLMENT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.enrolmentCaSigningKeys =  new KeyPair(publicSigningKey, privateSigningKey);
		
		PrivateKey privateEncryptionKey = readPrivateKeyFromFile(Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = readPublicKeyFromFile(Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.enrolmentCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
		
		this.enrolmentCaCertificate = readCertificateFromFile(Constants.ENROLMENT_CA_CERTIFICATE_FILE);
		this.enrolmentCaChain = new EtsiTs103097Certificate[] { this.enrolmentCaCertificate, this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] Enrolment CA certificate read from file");
	}

	private void createAuthorizationCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException {

		this.authorizationCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.authorizationCaSigningKeys.getPrivate(),
				Constants.AUTHORIZATION_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.authorizationCaSigningKeys.getPublic(),
				Constants.AUTHORIZATION_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.authorizationCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		writePrivateKeyToFile(this.authorizationCaEncryptionKeys.getPrivate(),
				Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		writePublicKeyToFile(this.authorizationCaEncryptionKeys.getPublic(),
				Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		String aAName = "AA.samuCA.autostrade.it";
		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000);
		ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 15);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.authorizationCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.authorizationCaEncryptionKeys.getPublic();

		this.authorizationCaCertificate = this.authorityCertGenerator.genAuthorizationCA(aAName, //
				authorityCAValidityPeriod, //
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
		this.authorizationCAChain = new EtsiTs103097Certificate[] { this.authorizationCaCertificate,
				this.rootCaCertificate };

		writeCertificateToFile(this.authorizationCaCertificate, Constants.AUTHORIZATION_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Authorization CA certificate written to file");
	}
	
	private void readAuthorizationCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException, ClassNotFoundException {

		PrivateKey privateSigningKey = readPrivateKeyFromFile(Constants.AUTHORIZATION_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = readPublicKeyFromFile(Constants.AUTHORIZATION_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.authorizationCaSigningKeys =  new KeyPair(publicSigningKey, privateSigningKey);
		
		PrivateKey privateEncryptionKey = readPrivateKeyFromFile(Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = readPublicKeyFromFile(Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.authorizationCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);

		this.authorizationCaCertificate = readCertificateFromFile(Constants.AUTHORIZATION_CA_CERTIFICATE_FILE);
		this.authorizationCAChain = new EtsiTs103097Certificate[] { this.authorizationCaCertificate,
				this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] Authorization CA certificate read from file");
	}

	static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

	public void generateCTL() throws Exception {
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

		writeCtlToFile(certificateTrustListMessage, "CTL.coer");
		Logger.shortPrint("[root CA         ] CTL written to file");

	}

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

	private ToBeSignedRcaCtl generateCtlRequest() throws Exception {
		final Version version = Version.V1;
		final Time32 nextUpdate = new Time32(dateFormat.parse("20250910 14:14:14"));
		final boolean isFullCtl = true;
		final int ctlSequence = 0;

		final Url itsAccessPoint = new Url("http://localhost:8080/samuCA/itss/dummy");
		final Url eaAccessPoint = new Url("http://localhost:8080/samuCA/enrolmentCA/");
		final Url aaAccessPoint = new Url("http://localhost:8080/samuCA/authorizationCA");
		final Url dcAccessPoint = new Url("http://localhost:8080/samuCA/dummy");

		HashedId8[] certificateDigests = { new HashedId8(this.rootCaCertificate.getEncoded()) };

		final CtlCommand[] ctlCommands = new CtlCommand[] { //
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
	
	private EtsiTs103097Certificate readCertificateFromFile(String filename)
			throws FileNotFoundException, IOException {
		DataInputStream dataInputStream = new DataInputStream(new FileInputStream(filename));
		
		EtsiTs103097Certificate certificate = new EtsiTs103097Certificate();
		certificate.decode(dataInputStream);;
		dataInputStream.close();

		return certificate;
	}

	private void writePrivateKeyToFile(PrivateKey privateKey, String filename) throws IOException {
		if (privateKey == null) {
			System.out.println("ERROR: key for " + filename + "is null.");
			System.exit(1);
		}
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(privateKey);
		objectOutputStream.close();
	}
	
	private void writePublicKeyToFile(PublicKey publicKey, String filename) throws IOException {
		if (publicKey == null) {
			System.out.println("ERROR: key for " + filename + "is null.");
			System.exit(1);
		}
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(publicKey);
		objectOutputStream.close();
	}

	private PrivateKey readPrivateKeyFromFile(String filename) throws IOException, ClassNotFoundException {
		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		PrivateKey privateKey = (PrivateKey) objectInputStream.readObject();
		objectInputStream.close();

		return privateKey;
	}
	
	private PublicKey readPublicKeyFromFile(String filename) throws IOException, ClassNotFoundException {
		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		PublicKey publicKey = (PublicKey) objectInputStream.readObject();
		objectInputStream.close();

		return publicKey;
	}

	public EtsiTs103097Certificate getRootCaCertificate() {
		return this.rootCaCertificate;
	}

	public EtsiTs103097Certificate getEnrolmentCaCertificate() {
		return this.enrolmentCaCertificate;
	}

	public KeyPair getEnrolmentCaSigningKeys() {
		return this.enrolmentCaSigningKeys;
	}

	public KeyPair getEnrolmentCaEncryptionKeys() {
		return this.enrolmentCaEncryptionKeys;
	}

	public EtsiTs103097Certificate[] getEnrolmentCaChain() {
		return this.enrolmentCaChain;
	}

	public EtsiTs103097Certificate getAuthorizationCaCertificate() {
		return this.authorizationCaCertificate;
	}

	public KeyPair getAuthorizationCaSigningKeys() {
		return this.authorizationCaSigningKeys;
	}

	public KeyPair getAuthorizationCaEncryptionKeys() {
		return this.authorizationCaEncryptionKeys;
	}

	public EtsiTs103097Certificate[] getAuthorizationCaChain() {
		return this.authorizationCAChain;
	}
}
