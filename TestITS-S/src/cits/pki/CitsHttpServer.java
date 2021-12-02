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

public class CitsHttpServer {

	private static ActorSystem<CitsHttpServer.Message> system;
	private static PKIEntities pki;

	public static void main(String[] args) throws Exception {
		setLogVerbosityToShortMessages();

		createPkiEntities();

		createActorSystem();
	}

	private static void createActorSystem() {
		system = ActorSystem.create(startServerAtLocalhost8080(), "SamuPkiActorSystem");

		exitIfSystemIsNull();
	}

	private static Behavior<Message> startServerAtLocalhost8080() {
		return CitsHttpServer.start("localhost", 8080);
	}

	public static Behavior<Message> start(String host, Integer port) {
		return Behaviors.setup(ctx -> {

			Route routes = createHttpRoutes();

			CompletionStage<ServerBinding> serverBinding = startServerAtTargetIpAndPort(host, port, routes);

			// TODO: understand
			ctx.pipeToSelf(serverBinding, (binding, failure) -> {
				if (binding != null)
					return new Started(binding);
				else
					return new StartFailed(failure);
			});

			return starting(false);
		});
	}

	private static void createPkiEntities() throws Exception {
		pki = new PKIEntities();
		
		exitIfPkiIsNull();
		
		pki.createAuthorities();
	}

	private static CompletionStage<ServerBinding> startServerAtTargetIpAndPort(String host, Integer port,
			Route routes) {
		CompletionStage<ServerBinding> serverBinding = Http.get(system).newServerAt(host, port).bind(routes);
		return serverBinding;
	}

	private static Route createHttpRoutes() {
		Route routes = new PkiRoutes(pki, system).createRoutes();
		return routes;
	}

	private static Behavior<Message> starting(boolean wasStopped) {
		return Behaviors.setup(ctx -> BehaviorBuilder.<Message>create().onMessage(StartFailed.class, failed -> {
			throw new RuntimeException("Server failed to start", failed.ex);
		}).onMessage(Started.class, msg -> {
			ctx.getLog().info("Server online at http://{}:{}", msg.binding.localAddress().getAddress(),
					msg.binding.localAddress().getPort());

			if (wasStopped)
				ctx.getSelf().tell(new Stop());

			return running(msg.binding);
		}).onMessage(Stop.class, s -> {
			// we got a stop message but haven't completed starting yet,
			// we cannot stop until starting has completed
			return starting(true);
		}).build());
	}

	private static Behavior<Message> running(ServerBinding binding) {
		return BehaviorBuilder.<Message>create().onMessage(Stop.class, msg -> Behaviors.stopped())
				.onSignal(PostStop.class, msg -> {
					binding.unbind();
					return Behaviors.same();
				}).build();
	}

	private static void setLogVerbosityToShortMessages() {
		Logger.setVerbosity(Logger.VerbosityLevel.SHORT_MESSAGES);
	}

	private static void exitIfPkiIsNull() {
		if (pki == null) {
			System.out.println("Error: pki is null");
			System.exit(1);
		}
	}
	
	private static void exitIfSystemIsNull() {
		if (system == null) {
			System.out.println("Error: system is null");
			System.exit(1);
		}
	}

	interface Message {
	}

	private static final class StartFailed implements Message {
		final Throwable ex;

		public StartFailed(Throwable ex) {
			this.ex = ex;
		}
	}

	private static final class Started implements Message {
		final ServerBinding binding;

		public Started(ServerBinding binding) {
			this.binding = binding;
		}
	}

	private static final class Stop implements Message {
	}
}
