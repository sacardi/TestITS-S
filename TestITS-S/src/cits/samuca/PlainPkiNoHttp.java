package cits.samuca;
//import akka.actor.typed.ActorSystem;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;

import cits.samuca.itss.ReceivingITSS;
import cits.samuca.itss.SendingITSS;
import cits.samuca.pki.PKIEntities;
import cits.samuca.utils.Logger;

public class PlainPkiNoHttp {
	private static PKIEntities pki;
	private static SendingITSS sendingITSS;
	private static ReceivingITSS receivingITSS;

	public static void main(String[] args) throws Exception {

		setVerbosityToShortMessages();

		createPkiInfrastructure();

		createSendingITSS();

		createReceivingITSS();

		final String messageToSend = "AAAA";
		sendCAM(messageToSend);

		// byte[] denm = sendingITSS.getDenm("Hello".getBytes());

//		pki.generateCTL();
	}

	private static void setVerbosityToShortMessages() {
		Logger.setVerbosity(Logger.VerbosityLevel.SHORT_MESSAGES);
	}

	private static void createPkiInfrastructure() throws Exception {
		pki = new PKIEntities();
	}

	private static void createSendingITSS() throws Exception {
		sendingITSS = pki.createSendingITSS();
	}

	private static void createReceivingITSS() throws NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		receivingITSS = pki.createReceivingITSS();
	}

	private static void sendCAM(final String message) throws IOException, GeneralSecurityException {
		byte[] cam = sendingITSS.getCam(message.getBytes());
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
	}
}
