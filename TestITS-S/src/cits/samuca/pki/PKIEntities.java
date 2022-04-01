package cits.samuca.pki;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.text.ParseException;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;

import cits.samuca.itss.ReceivingITSS;
import cits.samuca.itss.SendingITSS;
import cits.samuca.utils.Logger;

public class PKIEntities {

	private RootCa rootCA;
	private EnrolmentCA enrolmentCA;
	private AuthorizationCA authorizationCA;
	private TrustListManager trustListManager;

	private SendingITSS sendingItsStation;
	private ReceivingITSS receivingItsStation;

	public PKIEntities() throws Exception {
		createCertificationAuthorities();
	}

	private void createCertificationAuthorities() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		createRootCA();
		createEnrolmentCA();
		createAuthorizationCA();
		createTrustListManager();
		Logger.shortPrint("");
	}

	private void createRootCA() {
		this.rootCA = new RootCa();
		Logger.shortPrint("");
	}

	private void createEnrolmentCA() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		this.enrolmentCA = new EnrolmentCA();

		this.enrolmentCA.setCertificate(this.rootCA.getEnrolmentCaCertificate());
		this.enrolmentCA.setSigningKeys(this.rootCA.getEnrolmentCaSigningKeys());
		this.enrolmentCA.setEncrptionKeys(this.rootCA.getEnrolmentCaEncryptionKeys());
		this.enrolmentCA.setEnrolmentCaChain(this.rootCA.getEnrolmentCaChain());
	}

	private void createAuthorizationCA() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		this.authorizationCA = new AuthorizationCA();

		this.authorizationCA.setCertificate(this.rootCA.getAuthorizationCaCertificate());
		this.authorizationCA.setSigningKeys(this.rootCA.getAuthorizationCaSigningKeys());
		this.authorizationCA.setEncryptionKeys(this.rootCA.getAuthorizationCaEncryptionKeys());
		this.authorizationCA.setAuthorizationCaChain(this.rootCA.getAuthorizationCaChain());
	}

	private void createTrustListManager() {
		this.trustListManager = new TrustListManager(this.rootCA.getRootCaCertificate(), this.rootCA.getRootCaCertificateHashedId8());

	}

	// called only by PlainPkiNoHttp
	public SendingITSS createSendingITSS() throws Exception {

		// The security lifecycle of an ITS-S is:
		// Before init
		// Initialisation and Unenrolled
		// Enrolled and Unauthorised
		// Authorised for service
		// End of life
		//
		// This is defined in page 12 of ETSI TS 102 941 v 1.3.1

		// This is the sending ITS-S (e.g., a RSE)
		this.sendingItsStation = new SendingITSS();

		this.sendingItsStation.setEnrolmentCaCert(enrolmentCA.getCertificate());
		this.sendingItsStation.setAuthorizationCaCert(authorizationCA.getCertificate());
		this.sendingItsStation.setRootCaCert(rootCA.getRootCaCertificate());

		// Devo dare all'enrolment CA la mia chiave pubblica. Le credenziali sono create
		// dal manufacturer
		// e passate tramite un canale sicuro (102 941)
		// Non mi prendete in giro per l'IPC :)
		// send my ID to the enrolment CA, simulating an OOB channel
		// TODO: enrolmentCredCert at this point is empty. Maybe we should pass the
		// S-ITSS certificate, not the enrolment credentials
		this.enrolmentCA.setSendingItssIdAndCertificate(//
				this.sendingItsStation.getMyID(), //
				this.sendingItsStation.getEnrolmentCredCert());

		makeItsStationEnrolment();

		makeAuthorizationRequest();

		return this.sendingItsStation;
	}

	private void makeItsStationEnrolment() throws Exception, IOException, GeneralSecurityException,
			MessageParsingException, SignatureVerificationException, DecryptionFailedException, InternalErrorException {
		byte[] enrolmentMsgToSendToEnrolmentCa = getEnrolmentMessage();

		byte[] enrollmentResponse = getEnrolmentResponseFromEnrolmentCa(enrolmentMsgToSendToEnrolmentCa);

		this.sendingItsStation.finishEnrolment(enrollmentResponse);
	}

	private byte[] getEnrolmentMessage() throws Exception {
		byte[] enrolmentMsgToSendToEnrolmentCa = this.sendingItsStation.requestEnrolmentMessage();
		return enrolmentMsgToSendToEnrolmentCa;
	}

	public byte[] getEnrolmentResponseFromEnrolmentCa(byte[] enrolmentMsgToSendToEnrolmentCa)
			throws IOException, GeneralSecurityException, MessageParsingException, SignatureVerificationException,
			DecryptionFailedException, InternalErrorException {
		byte[] enrollmentResponse = this.enrolmentCA.enrollITSS(enrolmentMsgToSendToEnrolmentCa);
		return enrollmentResponse;
	}

	private void makeAuthorizationRequest()
			throws Exception, IOException, MessageParsingException, SignatureVerificationException,
			DecryptionFailedException, InternalErrorException, GeneralSecurityException, ParseException {
		byte[] authorizationMsgToSendToAuthorizationCA = this.sendingItsStation.requestAuthorization();
		// TODO: understand why I can comment out the following line and everything
		// works just fine
//		this.authorizationCA
//				.setAuthTicketEncKeysPublicKey(this.sendingItsStation.getAuthTicketEncryptionKeys().getPublic());
		this.authorizationCA.setAuthTicketSignKeysPublicKey(this.sendingItsStation.getAuthTicketSignKeys().getPublic());
		byte[] authorizationResponse = this.authorizationCA.authorize(authorizationMsgToSendToAuthorizationCA);
		this.sendingItsStation.setAuthorizationTicket(authorizationResponse);
	}

	public ReceivingITSS createReceivingITSS() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {
		receivingItsStation = new ReceivingITSS();
		receivingItsStation.setAuthorityCACertificate(authorizationCA.getCertificate());
		receivingItsStation.setRootCACertificate(rootCA.getRootCaCertificate());

		return this.receivingItsStation;
	}

}
