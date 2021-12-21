package cits.pki;

import java.util.concurrent.CompletionStage;

import akka.actor.typed.ActorSystem;
import akka.actor.typed.Behavior;
import akka.actor.typed.PostStop;
import akka.actor.typed.javadsl.ActorContext;
import akka.actor.typed.javadsl.BehaviorBuilder;
import akka.actor.typed.javadsl.Behaviors;
import akka.http.javadsl.Http;
import akka.http.javadsl.ServerBinding;
import akka.http.javadsl.server.Route;
import akka.japi.function.Function;
import cits.pki.httpserver.HttpServer;
import cits.pki.httpserver.HttpServerMessages;

public class MainFile {

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

		pki.createAuthorities();
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
