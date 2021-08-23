package it.mascanc.its.security;

public class Main {

	/**
	 * This is the main class for the test.
	 * 
	 * It should start a the following services:
	 * <ol>
	 * <li>A sending ITS station (this thread)</li>
	 * <li>A receiving ITS station</li>
	 * <li>A Enrollment Authority EA</li>
	 * <li>A Authorization Authority</li>
	 * <li>A root CA</li>
	 * </ol>
	 * After setting up all the threads it starts sending messages according with
	 * the relevant standards. Namely we have the following
	 * <ul>
	 * <li><b>Architecture</b>: 102 940</li>
	 * <li><b>Trust & Communication</b>: 102 731</li>
	 * <li><b>Message Format</b> related to the certificates, CA and DENM: 103
	 * 097</li>
	 * <li><b>Data Structure</b> such as Enrol Req/resp, Authz Req Resp, Authz Val
	 * Req/Resp: 102 941</li>
	 * </ul>
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		Logger.setVerbosity(Logger.VerbosityLevel.SHORT_MESSAGES);

		PKIEntities pki = new PKIEntities();
		pki.createAuthorities();

		SendingITSS sendingITSS = pki.createSendingITSS();
		ReceivingITSS receivingITSS = pki.createReceivingITSS();

		/*
		 * Now, if I am here without any exception, I am ready to send a message
		 */

		byte[] cam = sendingITSS.getCam("AAAA".getBytes());
		String received = new String("");
		try {
			received = receivingITSS.receive(cam);
		} catch (Exception e) {
			Logger.shortPrint("[main            ] 3) Receiving ITS-S receive failed:" + e);
		}
		Logger.debugPrint("[main            ] 3) Received message from receivingITSS: " + received);
		Logger.shortPrint("[main            ] 3) Received message from receivingITSS");
		Logger.shortPrint("");
		Logger.shortPrint("[main            ] Closing everything");
		//byte[] denm = sendingITSS.getDenm("Hello".getBytes());

	}
}
