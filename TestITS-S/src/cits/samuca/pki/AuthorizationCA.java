package cits.samuca.pki;

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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

/**
 * Simulates an authorization CA. They are defined in section 7.2.4, Subordinate
 * certification authority certificates.
 * 
 * @author max
 *
 */

// TODO: complete authorization ticket handling
public class AuthorizationCA {

	private static HashMap<String, EtsiTs103097Certificate> EnrolledItsStations = new HashMap<String, EtsiTs103097Certificate>();

	private EtsiTs103097Certificate myCertificate;

	private KeyPair signingKeys;

	private KeyPair encryptionKeys;

	private EtsiTs103097Certificate[] authorizationCaChain;

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

		this.signAlg = ecdsaNistP256;
		this.encryptionAlgorithm = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;
	}

	public byte[] authorize(byte[] authorizationMsgToSendToAuthorizationCA)
			throws IllegalArgumentException, IOException, MessageParsingException, SignatureVerificationException,
			DecryptionFailedException, InternalErrorException, GeneralSecurityException, ParseException {

		EtsiTs103097DataEncryptedUnicast authorizationTicketRequest = new EtsiTs103097DataEncryptedUnicast(
				authorizationMsgToSendToAuthorizationCA);

		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
				.getMessagesCaGenerator();

		Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(
				new Receiver[] { new CertificateReciever(this.encryptionKeys.getPrivate(), this.myCertificate) });

		// To decrypt the message and verify the external POP signature (not the inner
		// eCSignature signed for EA CA).
		boolean expectPoP = true;
		RequestVerifyResult<InnerAtRequest> verificationResult = messagesCaGenerator
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

		GeographicRegion region = PkiUtilsSingleton.getInstance().getGeographicRegion();

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

		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
				.getMessagesCaGenerator();

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
				PkiUtilsSingleton.getInstance().getCryptoManager());

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

	private ValidityPeriod setValidityPeriodForAuthorizationTicket() throws ParseException {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
		Date timeStamp = dateFormat.parse("20181202 12:12:21");
		ValidityPeriod authorizationTicketValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years,
				1);
		return authorizationTicketValidityPeriod;
	}

	public void setCertificate(EtsiTs103097Certificate cert) {
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

	public static HashMap<String, EtsiTs103097Certificate> getSits() {
		return EnrolledItsStations;
	}

	public void setAuthTicketSignKeysPublicKey(PublicKey authTicketSignKeysPublicKey) {
		this.authTicketSignKeysPublicKey = authTicketSignKeysPublicKey;
	}

	public void setAuthTicketEncKeysPublicKey(PublicKey authTicketEncKeysPublicKey) {
		this.authTicketEncKeysPublicKey = authTicketEncKeysPublicKey;
	}

}
