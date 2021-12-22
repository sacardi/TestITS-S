package cits.samuca;

import cits.samuca.httpserver.HttpServer;
import cits.samuca.pki.PKIEntities;
import cits.samuca.utils.Logger;

public class Main {

	private static PKIEntities pki;
	private static HttpServer server;

	public static void main(String[] args) throws Exception {
		setLogVerbosityToShortMessages();

		createPki();

		startServer();
	}

	private static void createPki() throws Exception {
		pki = new PKIEntities();

		exitIfPkiIsNull();
	}

	private static void startServer() {
		server = new HttpServer(pki);

		exitIfServerIsNull();
	}

	private static void exitIfPkiIsNull() {
		if (pki == null) {
			System.out.println("Error: pki is null");
			System.exit(1);
		}
	}

	private static void exitIfServerIsNull() {
		if (server == null) {
			System.out.println("Error: server is null");
			System.exit(1);
		}
	}

	private static void setLogVerbosityToShortMessages() {
		Logger.setVerbosity(Logger.VerbosityLevel.SHORT_MESSAGES);
	}

}
