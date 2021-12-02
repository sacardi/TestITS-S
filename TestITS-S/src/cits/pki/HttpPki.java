package cits.pki;

import java.util.concurrent.CompletionStage;

import akka.actor.typed.ActorRef;
import akka.actor.typed.ActorSystem;
import akka.actor.typed.Behavior;
import akka.actor.typed.PostStop;
import akka.actor.typed.javadsl.ActorContext;
import akka.actor.typed.javadsl.BehaviorBuilder;
import akka.actor.typed.javadsl.Behaviors;
import akka.http.javadsl.Http;
import akka.http.javadsl.ServerBinding;
import akka.http.javadsl.server.Route;
import cits.pki.HttpPki.Message;

public class HttpPki {

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
	
	private static ActorSystem<HttpPki.Message> system;
	private static PKIEntities pki;
	private static SendingITSS sendingITSS;
	private static ReceivingITSS receivingITSS;

	
	private static void createActorSystem() {
		system = ActorSystem.create(HttpPki.create("localhost", 8080), "SamuPki");
		if (system == null) {
			System.out.println("Error: system is null");
			System.exit(1);
		}
	}
	
	public static Behavior<Message> create(String host, Integer port) {
		return Behaviors.setup(ctx -> {

			createPkiInfrastructure();

			Route routes = createRoutes(ctx);

			CompletionStage<ServerBinding> serverBinding = startServerAtTargetIpAndPort(host, port, routes);

			ctx.pipeToSelf(serverBinding, (binding, failure) -> {
				if (binding != null)
					return new Started(binding);
				else
					return new StartFailed(failure);
			});

			return starting(false);
		});
	}
	
	private static void createPkiInfrastructure() throws Exception {
		pki = new PKIEntities();
		pki.createAuthorities();
	}

	private static CompletionStage<ServerBinding> startServerAtTargetIpAndPort(String host, Integer port,
			Route routes) {
		CompletionStage<ServerBinding> serverBinding = Http.get(system).newServerAt(host, port).bind(routes);
		return serverBinding;
	}

	private static Route createRoutes(ActorContext<Message> ctx) {
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

	private static void setVerbosityToShortMessages() {
		Logger.setVerbosity(Logger.VerbosityLevel.SHORT_MESSAGES);
	}
	
	public static void main(String[] args) {
		setVerbosityToShortMessages();
		
		createActorSystem();
	}
}
