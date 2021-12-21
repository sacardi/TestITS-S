package cits.pki.httpserver;

import java.util.concurrent.CompletionStage;

import akka.actor.typed.Behavior;
import akka.actor.typed.PostStop;
import akka.actor.typed.javadsl.ActorContext;
import akka.actor.typed.javadsl.BehaviorBuilder;
import akka.actor.typed.javadsl.Behaviors;
import akka.http.javadsl.Http;
import akka.http.javadsl.ServerBinding;
import akka.http.javadsl.server.Route;
import akka.japi.function.Function;
import cits.pki.PKIEntities;
import cits.pki.PkiRoutes;

import akka.actor.typed.ActorSystem;

public class HttpServer {


	private static ActorSystem<HttpServerMessages.Message> system;
	private static PKIEntities pki;
	
	public HttpServer(PKIEntities entities)
	{
		pki = entities;
		createActorSystem();
	}


	private void createActorSystem() {
		system = ActorSystem.create(startServerAtLocalhost8080(), "SamuPkiActorSystem");
		
		exitIfSystemIsNull();
	}
	

	private static Behavior<HttpServerMessages.Message> startServerAtLocalhost8080() {
		return start("localhost", 8080);
	}
	
	private static void exitIfSystemIsNull() {
		if (system == null) {
			System.out.println("Error: system is null");
			System.exit(1);
		}
	}
	
	public static void sendServerBindingMessageToSelfIfBindingWasSuccessful(
			ActorContext<HttpServerMessages.Message> ctx, CompletionStage<ServerBinding> serverBinding) {
		// TODO: understand
		ctx.pipeToSelf(serverBinding, (binding, failure) -> {
			if (binding != null)
				return new HttpServerMessages.Started(binding);
			else
				return new HttpServerMessages.StartFailed(failure);
		});
	}

	public static Behavior<HttpServerMessages.Message> start(String host, Integer port) {
		return Behaviors.setup(ctx -> {

			Route routes = createHttpRoutes();

			CompletionStage<ServerBinding> serverBinding = startServerAtTargetIpAndPort(host, port, routes);

			HttpServer.sendServerBindingMessageToSelfIfBindingWasSuccessful(ctx, serverBinding);

			return HttpServer.starting(false);
		});
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

	private static Behavior<HttpServerMessages.Message> starting(boolean wasStopped) {
		return Behaviors.setup(ctx -> createMessageHandlers(wasStopped, ctx));
	}

	private static Behavior<HttpServerMessages.Message> createMessageHandlers(boolean wasStopped,
			ActorContext<HttpServerMessages.Message> ctx) {
		return BehaviorBuilder.<HttpServerMessages.Message>create()
				.onMessage(HttpServerMessages.StartFailed.class, handleStartFailedMessage())
				.onMessage(HttpServerMessages.Started.class, handleStartedMessage(wasStopped, ctx))
				.onMessage(HttpServerMessages.Stop.class, handleStopMessage()).build();
	}

	private static Function<HttpServerMessages.StartFailed, Behavior<HttpServerMessages.Message>> handleStartFailedMessage() {
		return failed -> {
			throw new RuntimeException("Server failed to start", failed.ex);
		};
	}

	private static Function<HttpServerMessages.Stop, Behavior<HttpServerMessages.Message>> handleStopMessage() {
		return s -> {
			// we got a stop message but haven't completed starting yet,
			// we cannot stop until starting has completed
			return starting(true);
		};
	}

	private static Function<HttpServerMessages.Started, Behavior<HttpServerMessages.Message>> handleStartedMessage(
			boolean wasStopped, ActorContext<HttpServerMessages.Message> ctx) {
		return msg -> {
			ctx.getLog().info("Server online at http://{}:{}", msg.binding.localAddress().getAddress(),
					msg.binding.localAddress().getPort());

			if (wasStopped)
				ctx.getSelf().tell(new HttpServerMessages.Stop());

			return running(msg.binding);
		};
	}

	private static Behavior<HttpServerMessages.Message> running(ServerBinding binding) {
		return BehaviorBuilder.<HttpServerMessages.Message>create()
				.onMessage(HttpServerMessages.Stop.class, msg -> Behaviors.stopped()).onSignal(PostStop.class, msg -> {
					binding.unbind();
					return Behaviors.same();
				}).build();
	}

}
