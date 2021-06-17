package it.mascanc.its.security;

public class PKIEntities {

	public RootCA rootCA;
	public EnrollmentCA enrollmentCA;
	public AuthorizationCA authorizationCA;
	public SendingITSS sits;
	public ReceivingITS ritss;

	public PKIEntities() {
	}

	public void createAuthorities() {
		try {
			createRootCA();
			createEnrollmentCA();
			createAuthorizationCA();
		} catch (Exception e) {
			System.out.println("Exception during CA initialization:" + e);
			System.exit(1);
		}
	}

	private void createRootCA() throws Exception {
		rootCA = new RootCA();
	}

	private void createEnrollmentCA() throws Exception {
		enrollmentCA = new EnrollmentCA();

		enrollmentCA.setCertificate(rootCA.getEnrollmentCACertificate());
		enrollmentCA.setSigningKeys(rootCA.getEnrollmentCASigningKeys());
		enrollmentCA.setEncrptionKeys(rootCA.getEnrollmentCAEncryptionKeys());
		enrollmentCA.setEnrolmentCAChain(rootCA.getEnrollmentCAChain());
	}

	private void createAuthorizationCA() throws Exception {
		authorizationCA = new AuthorizationCA();

		authorizationCA.setCertificate(rootCA.getAuthorizationCACertificate());
		authorizationCA.setSigningKeys(rootCA.getAuthorizationCASigningKeys());
		authorizationCA.setEncryptionKeys(rootCA.getAuthorizationCAEncryptionKeys());
		authorizationCA.setAuthorizationCAChain(rootCA.getAuthorizationCAChain());
	}

	public void rest_of_the_code() {
		try {

			/*
			 * Now, if I am here without any exception, I am ready to send a message
			 */
			byte[] cam = sits.sendCAMMessage("Ciao".getBytes());

			ReceivingITS ritss = new ReceivingITS();
			ritss.setAuthorityCACertificate(authorizationCA.getCertificate());
			ritss.setRootCACertificate(rootCA.getMyCertificate());
			String received = ritss.receive(cam);
			System.out.println("Received: " + received);
			System.out.println("Closing everything");
		} catch (Exception e) {
			System.out.println(e);
		}
	}

	public SendingITSS createSendingITSS() throws Exception {
		// TODO Auto-generated method stub
		/*
		 * The security lifecycle of an ITS-S is Before init Initialisation and
		 * Unenrolled Enrolled and Unauthorised Authorised for service End of life
		 * 
		 * This is defined in page 12 of ETSI TS 102 941 v 1.3.1
		 * 
		 */

		// This is the sending ITS-S (e.g., a RSE)
		try {
			this.sits = new SendingITSS();
		} catch (Exception e) {
			System.out.println("Exception during initialization of sending ITS-S:");
			System.out.println(e);
			System.exit(1);
		}
		sits.setEnrolmentCaCert(enrollmentCA.getCertificate());
		sits.setAuthorizationCaCert(authorizationCA.getCertificate());
		sits.setRootCACert(rootCA.getRootCACertificate());

		// Devo dare all'enrolment CA la mia chiave pubblica. Le credenziali sono create
		// dal manufacturer
		// e passate tramite un canale sicuro (102 941)
		// Non mi prendete in giro per l'IPC :)

		// sent my ID to the enrolment CA, simulating an OOB channel
		CAandID sits_ca_and_id = new CAandID(sits.getMyID(), sits.getEnrolmentCredCert());
		enrollmentCA.setSitsId(sits_ca_and_id);

		/*
		 * ENROLMENT
		 */
		byte[] enrolmentMSgToSendToEnrolmentCA = sits.requestEnrolment();
		// Ora lo devo mandare a EnrolCA
		byte[] enrollmentResponse = enrollmentCA.enrollITS(enrolmentMSgToSendToEnrolmentCA);
		sits.finishEnrolment(enrollmentResponse);

		/*
		 * AUTHORIZATION
		 */
		// Set some certificate chain
		// authorizationCA.setEnrollmentCredCertChain(sits.getEnrolmenCredChain());
		// authorizationCA.setEnrolCAEncKeys(enrollmentCA.getEncryptionKeys());
		// authorizationCA.setEnrolmentCACert(enrollmentCA.getCertificate());

		byte[] authorizationMsgToSendToAuthorizationCA = sits.requestAuthorizationFor("CAM");
		authorizationCA.setAuthTicketEncKeysPublicKey(sits.getAuthTicketEncryptionKeys().getPublic());
		authorizationCA.setAuthTicketSignKeysPublicKey(sits.getAuthTicketSignKeys().getPublic());
		byte[] authorizationResponse = authorizationCA.authorize(authorizationMsgToSendToAuthorizationCA);
		sits.setAuthorizationTicket(authorizationResponse);
		
		return this.sits;
	}

	public ReceivingITS createReceivingITSS() {
		try {
			ritss = new ReceivingITS();
		} catch (Exception e) {
			System.out.println("Exception during initialization of receiving ITS-S:");
			System.out.println(e);
			System.exit(1);
		}
		ritss.setAuthorityCACertificate(authorizationCA.getCertificate());
		ritss.setRootCACertificate(rootCA.getMyCertificate());

		return this.ritss;
	}
}
