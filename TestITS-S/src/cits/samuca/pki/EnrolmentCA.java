package cits.samuca.pki;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import cits.samuca.utils.Constants;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

/**
 * They are defined in section 7.2.4, Subordinate certification authority
 * certificates.
 * 
 * <h1>CA Certificate Request</h1> In 102 941 the certificate request for the CA
 * shall be sent by an off-band mechanism (section 6.2.1). The trust is defined
 * by the EU commission document
 * 
 * @author max
 *
 */
public class EnrolmentCA {
	// This is the hashmap of the sending its. The Enrolment CA already knows the
	// ITS, and it shall know the permissions,
	// and the validity period and region.
	public static HashMap<String, EtsiTs103097Certificate> SendingItsStations = new HashMap<String, EtsiTs103097Certificate>();

	// This is the list of enrolled SITS
	public static HashMap<String, EtsiTs103097Certificate> EnrolledSendingItsStations = new HashMap<String, EtsiTs103097Certificate>();
	// Crypto stuff that I need.
	private EtsiTs103097Certificate myCertificate;

	private KeyPair signingKeys;

	private KeyPair encryptionKeys;

	private EtsiTs103097Certificate[] enrolmentCaChain;

	public EnrolmentCA() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
	}

	public EtsiTs103097Certificate getCertificate() {
		return this.myCertificate;
	}

	public void setCertificate(EtsiTs103097Certificate cert) {
//		Logger.debugPrint("[enrolment CA    ] 0a) obtained certificate " + cert);
		Logger.shortPrint("[enrolment CA    ] 0a) obtained certificate");
		this.myCertificate = cert;
	}

	public void setSigningKeys(KeyPair keys) {
		Logger.debugPrint("[enrolment CA    ] 0a) obtained keys " + keys);
		Logger.shortPrint("[enrolment CA    ] 0a) obtained keys");
		this.signingKeys = keys;
	}

	public void setEncrptionKeys(KeyPair enrollmentCAEncryptionKeys) {
		this.encryptionKeys = enrollmentCAEncryptionKeys;
	}

	public void setEnrolmentCaChain(EtsiTs103097Certificate[] enrollmentCaChain) {
		this.enrolmentCaChain = enrollmentCaChain;
	}

	/**
	 * This method stores the Sending ITS-S id and its public key.
	 * 
	 * @param sits_ca_and_id
	 */
//	public void setSendingITSSId(CAandID sits_ca_and_id) {
//		System.out.println("Received initializion data for ITS-S " + sits_ca_and_id.getMyID());
//		SendingITSStations.put(sits_ca_and_id.getMyID(), sits_ca_and_id.getPublicKey());
//	}

	public void setSendingItssIdAndCertificate(String sendingItssId, EtsiTs103097Certificate enrolmentCredentialsCert) {
		SendingItsStations.put(sendingItssId, enrolmentCredentialsCert);
	}

	/**
	 * This method enrols an ITS station
	 * 
	 * @param enrolmentMSgToSendToEnrolmentCA
	 * @return the byte[] encoded enrolment response.
	 * @throws IOException
	 * @throws IllegalArgumentException
	 * @throws GeneralSecurityException
	 * @throws InternalErrorException
	 * @throws DecryptionFailedException
	 * @throws SignatureVerificationException
	 * @throws MessageParsingException
	 */
	public byte[] enrollITS(byte[] enrolmentMSgToSendToEnrolmentCA)
			throws IllegalArgumentException, IOException, GeneralSecurityException, MessageParsingException,
			SignatureVerificationException, DecryptionFailedException, InternalErrorException {

		RequestVerifyResult<InnerEcRequest> innerEcRequest = getEnrolmentRequestResultFromEncryptedMessage(
				enrolmentMSgToSendToEnrolmentCA);

		EtsiTs103097DataEncryptedUnicast enrolmentResponse = createEnrolmentResponse(innerEcRequest);

		return enrolmentResponse.getEncoded();
	}

	private RequestVerifyResult<InnerEcRequest> getEnrolmentRequestResultFromEncryptedMessage(
			byte[] enrolmentMSgToSendToEnrolmentCA) throws IOException, GeneralSecurityException,
			MessageParsingException, SignatureVerificationException, DecryptionFailedException, InternalErrorException {
		EtsiTs103097DataEncryptedUnicast encryptedMessage = new EtsiTs103097DataEncryptedUnicast(
				enrolmentMSgToSendToEnrolmentCA);

		RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = decryptEnrolmentRequest(encryptedMessage);
		return enrolmentRequestResult;
	}

	private RequestVerifyResult<InnerEcRequest> decryptEnrolmentRequest(
			EtsiTs103097DataEncryptedUnicast encryptedMessage) throws IOException, GeneralSecurityException,
			MessageParsingException, SignatureVerificationException, DecryptionFailedException, InternalErrorException {
		// Then create a receiver store to decrypt the message
		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
				.getMessagesCaGenerator();

		Map<HashedId8, Receiver> enrolCaReceipients = messagesCaGenerator.buildRecieverStore(
				new Receiver[] { new CertificateReciever(this.encryptionKeys.getPrivate(), this.myCertificate) });

		// Now try to decrypt:
		RequestVerifyResult<InnerEcRequest> innerEcRequest = messagesCaGenerator
				.decryptAndVerifyEnrolmentRequestMessage(encryptedMessage, null, null, enrolCaReceipients);

		Logger.shortPrint("[enrolment CA    ] 1) Received a enrolment request message from: "
				+ innerEcRequest.getSignerIdentifier());
		Logger.debugPrint("[enrolment CA    ] 1) Header info" + innerEcRequest.getHeaderInfo());
		Logger.debugPrint("[enrolment CA    ] 1) The inner message " + innerEcRequest.getValue());
		return innerEcRequest;
	}

	private EtsiTs103097DataEncryptedUnicast createEnrolmentResponse(
			RequestVerifyResult<InnerEcRequest> enrolmentRequestResult)
			throws SignatureException, IOException, GeneralSecurityException {
//		byte[] itssId = getItssId(enrolmentRequestResult);

		InnerEcResponse innerEcResponse = null;

		// XXX: UNCOMMENT / CHANGE -- begin
		// here I should check that the itsID is one of the S-ITSS that I've already
		// visited
//		boolean sendingItssIsKnown = SendingItsStations.containsKey(new String(itssId));
		boolean sendingItssIsKnown = true;
		// XXX: UNCOMMENT / CHANGE -- end
		if (sendingItssIsKnown) {
			EtsiTs103097Certificate enrolmentCredential = createEnrolmentCredentialForItss();
			innerEcResponse = createPositiveInnerEcResponse(enrolmentRequestResult, enrolmentCredential);
		} else {
			innerEcResponse = createNegativeInnerEcResponse(enrolmentRequestResult);
		}

		EtsiTs103097DataEncryptedUnicast encryptedEnrolmentResponse = encryptEnrolmentResponse(enrolmentRequestResult,
				innerEcResponse);
		return encryptedEnrolmentResponse;
	}

//	private byte[] getItssId(RequestVerifyResult<InnerEcRequest> enrolmentRequestResult) {
//		InnerEcRequest msgRequest = enrolmentRequestResult.getValue();
//		byte[] itsId = msgRequest.getItsId();
//
//		Logger.shortPrint("[enrolment CA    ] 1) The ITS id received is " + new String(itsId));
//		// let me get the information for this ITS ID
//		return itsId;
//	}

	private EtsiTs103097Certificate createEnrolmentCredentialForItss() throws SignatureException, IOException {
		Logger.shortPrint("[enrolment CA    ] 1) The S-ITS-S is known, generating its certificate");

		final DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(
				cryptoManager);
		SignatureChoices signingAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		KeyPair enrollmentCredentialSigningKeys = cryptoManager.generateKeyPair(signingAlgorithm);
		KeyPair enrollmentCredentialEncryptionKeys = cryptoManager.generateKeyPair(signingAlgorithm);

		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);

		GeographicRegion region = setRegionToItaly();

		// THIS IS A UNIQUE ID FOR THE CERTIFICATE THAT IT WILL BE USED BY THE
		// AA TO CHECK IF THIS CERT IS VALID (section 6.2.3.3.1)
		String certificateHolder = UUID.randomUUID().toString();

		// TODO: understand what it means
		// SSP data set in SecuredCertificateRequestService appPermission, two byte, for
		// example: 0x01C0s
		byte[] sspData = Hex.decode("01C0");

		int assuranceLevel = 1;
		int confidenceLevel = 3;
		EtsiTs103097Certificate signerCertificate = this.myCertificate;

		PublicKey signinPublicKey = enrollmentCredentialSigningKeys.getPublic();
		SymmAlgorithm symmetricAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices encryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		EtsiTs103097Certificate enrollmentCredential = enrollmentCredentialCertGenerator.genEnrollCredential(
				certificateHolder, //
				validityPeriod, //
				region, //
				sspData, //
				assuranceLevel, //
				confidenceLevel, //
				signingAlgorithm, //
				signinPublicKey, // signPublicKey, i.e public key in certificate
				signerCertificate, // signerCertificate
				this.signingKeys.getPublic(), // signCertificatePublicKey,
				this.signingKeys.getPrivate(), //
				symmetricAlgorithm, // symmAlgorithm
				encryptionAlgorithm, // encPublicKeyAlgorithm
				enrollmentCredentialEncryptionKeys.getPublic() // encryption public key
		);
		return enrollmentCredential;
	}

	private GeographicRegion setRegionToItaly() {
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION_ITALY);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);
		return region;
	}

	private InnerEcResponse createPositiveInnerEcResponse(RequestVerifyResult<InnerEcRequest> enrolmentRequestResult,
			EtsiTs103097Certificate enrolmentCredentials) {
		InnerEcResponse innerEcResponse;
		innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(), EnrollmentResponseCode.ok,
				enrolmentCredentials);
		return innerEcResponse;
	}

	private InnerEcResponse createNegativeInnerEcResponse(RequestVerifyResult<InnerEcRequest> enrolmentRequestResult) {
		InnerEcResponse innerEcResponse;
		Logger.shortPrint("Ths S-ITS-S is UNKNOWN");
		innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(),
				EnrollmentResponseCode.unknownits, null);
		return innerEcResponse;
	}

	private EtsiTs103097DataEncryptedUnicast encryptEnrolmentResponse(
			RequestVerifyResult<InnerEcRequest> enrolmentRequestResult, InnerEcResponse innerEcResponse)
			throws IOException, GeneralSecurityException {
		Time64 generationTime = new Time64(new Date());
		EtsiTs103097Certificate[] signerCertificateChain = this.enrolmentCaChain;
		PrivateKey signerPrivateKey = this.signingKeys.getPrivate();
		SymmAlgorithm encryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		SecretKey preSharedKey = enrolmentRequestResult.getSecretKey();

		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
				.getMessagesCaGenerator();

		EtsiTs103097DataEncryptedUnicast enrolmentResponseMessage = messagesCaGenerator.genEnrolmentResponseMessage(
				generationTime, //
				innerEcResponse, //
				signerCertificateChain, //
				signerPrivateKey, //
				encryptionAlgorithm, //
				preSharedKey); //
		return enrolmentResponseMessage;
	}

	public KeyPair getEncryptionKeys() {
		return this.encryptionKeys;
	}

}
