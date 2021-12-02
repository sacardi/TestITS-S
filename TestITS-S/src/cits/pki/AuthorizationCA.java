package cits.pki;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.text.ParseException;
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
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

/**
 * Simulates an authorization CA. They are defined in section 7.2.4, Subordinate
 * certification authority certificates.
 * 
 * @author max
 *
 */
public class AuthorizationCA {
	public static final int port = 8888;

	// these are the enrolled SITS
	private static HashMap<String, EtsiTs103097Certificate> SendingItsStations = new HashMap<String, EtsiTs103097Certificate>();

	// Stuff that I need for the crypto.
	private EtsiTs103097Certificate myCertificate;

	private KeyPair signingKeys;

	private KeyPair encryptionKeys;

	private EtsiTs103097Certificate[] authorizationCaChain;

	private ETSITS102941MessagesCaGenerator messagesCaGenerator;

	private DefaultCryptoManager cryptoManager;

//	private EtsiTs103097Certificate rootCaCert;
//
//	private EtsiTs103097Certificate[] enrollmentCredCertChain;
//
//	private KeyPair enrolCAEncKeys;
//
//	private Certificate enrolmentCACert;

	private PublicVerificationKeyChoices signAlg;

	private BasePublicEncryptionKeyChoices encryptionAlgorithm;

	private PublicKey authTicketSignKeysPublicKey;

	private PublicKey authTicketEncKeysPublicKey;

	public EtsiTs103097Certificate getCertificate() {
		return this.myCertificate;
	}

	public AuthorizationCA() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		init();
	}

	private void init() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		setupCryptoManager();

		setCaMessagesGenerator();

		this.signAlg = ecdsaNistP256;
		this.encryptionAlgorithm = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;
	}

	private void setupCryptoManager() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		// Create a crypto manager in charge of communicating with underlying
		// cryptographic components
		this.cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	}

	private void setCaMessagesGenerator() throws SignatureException {
		int versionToGenerate = Ieee1609Dot2Data.DEFAULT_VERSION;
		HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
		SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaNistP256Signature;

		// Create a ETSITS102941MessagesCaGenerator generator
		messagesCaGenerator = new ETSITS102941MessagesCaGenerator(versionToGenerate, //
				this.cryptoManager, //
				digestAlgorithm, //
				signatureScheme);

	}

	/**
	 * This method takes an authorization request, and returns with the ticket.
	 * 
	 * @param authorizationMsgToSendToAuthorizationCA
	 * @return
	 * @throws IOException
	 * @throws IllegalArgumentException
	 * @throws InternalErrorException
	 * @throws DecryptionFailedException
	 * @throws SignatureVerificationException
	 * @throws MessageParsingException
	 * @throws GeneralSecurityException
	 * @throws ParseException
	 */
	public byte[] authorize(byte[] authorizationMsgToSendToAuthorizationCA)
			throws IllegalArgumentException, IOException, MessageParsingException, SignatureVerificationException,
			DecryptionFailedException, InternalErrorException, GeneralSecurityException, ParseException {
		EtsiTs103097DataEncryptedUnicast authorizationTicketRequest = new EtsiTs103097DataEncryptedUnicast(
				authorizationMsgToSendToAuthorizationCA);
		// Build a recipient store for Authorization Authority
		Map<HashedId8, Receiver> authorizationCAReceipients = this.messagesCaGenerator.buildRecieverStore(
				new Receiver[] { new CertificateReciever(this.encryptionKeys.getPrivate(), this.myCertificate) });

		// To decrypt the message and verify the external POP signature (not the inner
		// eCSignature signed for EA CA).
		boolean expectPoP = true;
		RequestVerifyResult<InnerAtRequest> verificationResult = this.messagesCaGenerator
				.decryptAndVerifyAuthorizationRequestMessage(//
						authorizationTicketRequest, //
						expectPoP, //
						authorizationCAReceipients);

		// The AuthorizationRequestData contains the innerAtRequest and calculated
		// requestHash
		InnerAtRequest innerAtRequest = verificationResult.getValue();
		Logger.shortPrint("[authorization CA] 2) Got an authorization request from "
				+ innerAtRequest.getSharedAtRequest().getRequestedSubjectAttributes().getId());

		// Ok, qui ho da fare il check sui permessi, ci saranno access control.

		ValidityPeriod authorizationTicketValidityPeriod = setValidityPeriodForAuthorizationTicket();

		GeographicRegion region = setRegionToItaly();

		// This is the InnerEcRequest. The outer parts are Data-Signed and Encrypted.
		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(
				ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
		PsidSsp[] appPermissions = new PsidSsp[] { appPermCertMan };

		EtsiTs103097Certificate authorizationTicketCertificate = generateAuthorizationTicketCertificate(
				authorizationTicketValidityPeriod, region, appPermissions);

		// TODO: where is the call to the EA (and relative response)?
		EtsiTs103097DataEncryptedUnicast authResponseMessage = generateAuthorizationResponse(verificationResult,
				authorizationTicketCertificate);

		return authResponseMessage.getEncoded();
	}

	private EtsiTs103097DataEncryptedUnicast generateAuthorizationResponse(
			RequestVerifyResult<InnerAtRequest> verificationResult,
			EtsiTs103097Certificate authorizationTicketCertificate) throws IOException, GeneralSecurityException {
		InnerAtResponse innerAtResponse = new InnerAtResponse(verificationResult.getRequestHash(),
				AuthorizationResponseCode.ok, authorizationTicketCertificate);

		EtsiTs103097DataEncryptedUnicast authResponseMessage = messagesCaGenerator.genAuthorizationResponseMessage(
				new Time64(new Date()), // generation Time
				innerAtResponse, authorizationCaChain, // The AA certificate chain signing the message
				signingKeys.getPrivate(), SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
				verificationResult.getSecretKey()); // The symmetric key generated in the request.
		return authResponseMessage;
	}

	private EtsiTs103097Certificate generateAuthorizationTicketCertificate(
			ValidityPeriod authorizationTicketValidityPeriod, GeographicRegion region, PsidSsp[] appPermissions)
			throws SignatureException, IOException {
		ETSIAuthorizationTicketGenerator authorizationTicketGenerator = new ETSIAuthorizationTicketGenerator(
				this.cryptoManager);

		EtsiTs103097Certificate authorizationTicketCertificate = authorizationTicketGenerator.genAuthorizationTicket(//
				authorizationTicketValidityPeriod, //
				region, //
				new SubjectAssurance(2, 1), //
				appPermissions, //
				signAlg, //
				authTicketSignKeysPublicKey, //
				myCertificate, //
				signingKeys.getPublic(), //
				signingKeys.getPrivate(), //
				SymmAlgorithm.aes128Ccm, //
				encryptionAlgorithm, //
				authTicketEncKeysPublicKey);
		return authorizationTicketCertificate;
	}

	private GeographicRegion setRegionToItaly() {
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);
		return region;
	}

	private ValidityPeriod setValidityPeriodForAuthorizationTicket() throws ParseException {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
		Date timeStamp = dateFormat.parse("20181202 12:12:21");
		ValidityPeriod authorizationTicketValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years,
				1);
		return authorizationTicketValidityPeriod;
	}

	public void setCertificate(EtsiTs103097Certificate cert) {
		Logger.debugPrint("[authorization CA] 0b) obtained certificate: " + cert);
		Logger.shortPrint("[authorization CA] 0b) obtained certificate");
		this.myCertificate = cert;
	}

	public EtsiTs103097Certificate getMyCertificate() {
		return myCertificate;
	}

	public void setMyCertificate(EtsiTs103097Certificate myCertificate) {
		this.myCertificate = myCertificate;
	}

	public KeyPair getSigningKeys() {
		return signingKeys;
	}

	public void setSigningKeys(KeyPair signingKeys) {
		Logger.debugPrint("[authorization CA] 0b) obtained keys " + signingKeys);
		Logger.shortPrint("[authorization CA] 0b) obtained keys");
		this.signingKeys = signingKeys;
	}

	public KeyPair getEncryptionKeys() {
		return encryptionKeys;
	}

	public void setEncryptionKeys(KeyPair encryptionKeys) {
		this.encryptionKeys = encryptionKeys;
	}

	public EtsiTs103097Certificate[] getAuthorizationCaChain() {
		return authorizationCaChain;
	}

	public void setAuthorizationCaChain(EtsiTs103097Certificate[] authorizationCaChain) {
		this.authorizationCaChain = authorizationCaChain;
	}

	public ETSITS102941MessagesCaGenerator getMessagesCaGenerator() {
		return messagesCaGenerator;
	}

	public void setMessagesCaGenerator(ETSITS102941MessagesCaGenerator messagesCaGenerator) {
		this.messagesCaGenerator = messagesCaGenerator;
	}

	public DefaultCryptoManager getCryptoManager() {
		return cryptoManager;
	}

	public void setCryptoManager(DefaultCryptoManager cryptoManager) {
		this.cryptoManager = cryptoManager;
	}

	public static int getPort() {
		return port;
	}

	public static HashMap<String, EtsiTs103097Certificate> getSits() {
		return SendingItsStations;
	}

	public void setAuthTicketSignKeysPublicKey(PublicKey authTicketSignKeysPublicKey) {
		this.authTicketSignKeysPublicKey = authTicketSignKeysPublicKey;
	}

	public void setAuthTicketEncKeysPublicKey(PublicKey authTicketEncKeysPublicKey) {
		this.authTicketEncKeysPublicKey = authTicketEncKeysPublicKey;
	}

}
