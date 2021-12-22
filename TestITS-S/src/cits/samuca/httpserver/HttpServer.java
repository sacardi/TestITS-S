package cits.samuca.httpserver;

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
import cits.samuca.httpserver.HttpServerMessages.Message;
import cits.samuca.pki.PKIEntities;
import akka.actor.typed.ActorSystem;

public class HttpServer {

	private ActorSystem<HttpServerMessages.Message> actorSystem;
	private PKIEntities pki;

	private String address = "localhost";
	private Integer port = 8080;

	public HttpServer(PKIEntities pki) {
		this.pki = pki;

		createActorSystem();
	}

	private void createActorSystem() {
		this.actorSystem = ActorSystem.create(startServer(), "SamuPkiActorSystem");

		exitIfSystemIsNull();
	}

	public Behavior<HttpServerMessages.Message> startServer() {
		return Behaviors.setup(ctx -> {

			Route httpRoutes = createHttpRoutes();

			startServerWithCustomHttpRoutes(ctx, httpRoutes);

			return handleSuccessAndFailure();
		});
	}

	private Route createHttpRoutes() {
		Route routes = new PkiRoutes(this.pki, this.actorSystem).createRoutes();
		return routes;
	}

	private void startServerWithCustomHttpRoutes(ActorContext<Message> ctx, Route httpRoutes) {
		CompletionStage<ServerBinding> binding = createServerAndBindRoutes(httpRoutes);

		sendSuccessOrFailureAccordingToBindingValue(ctx, binding);
	}

	private CompletionStage<ServerBinding> createServerAndBindRoutes(Route routes) {
		CompletionStage<ServerBinding> serverBinding = Http.get(this.actorSystem).newServerAt(this.address, this.port)
				.bind(routes);
		return serverBinding;
	}

	public void sendSuccessOrFailureAccordingToBindingValue(ActorContext<HttpServerMessages.Message> ctx,
			CompletionStage<ServerBinding> serverBinding) {

		ctx.pipeToSelf(serverBinding, (binding, failure) -> {
			if (binding != null)
				return new HttpServerMessages.StartSucceeded(binding);
			else
				return new HttpServerMessages.StartFailed(failure);
		});
	}

	private Behavior<HttpServerMessages.Message> handleSuccessAndFailure() {
		return Behaviors.setup(ctx -> createMessageHandlersForSuccessAndFailure(ctx));
	}

	private Behavior<HttpServerMessages.Message> createMessageHandlersForSuccessAndFailure(ActorContext<HttpServerMessages.Message> ctx) {
		return BehaviorBuilder.<HttpServerMessages.Message>create()
				.onMessage(HttpServerMessages.StartFailed.class, handleStartFailed())
				.onMessage(HttpServerMessages.StartSucceeded.class, handleStartSucceeded(ctx)).build();
	}

	private Function<HttpServerMessages.StartFailed, Behavior<HttpServerMessages.Message>> handleStartFailed() {
		return failed -> {
			throw new RuntimeException("Server failed to start", failed.ex);
		};
	}

	private Function<HttpServerMessages.StartSucceeded, Behavior<HttpServerMessages.Message>> handleStartSucceeded(
			ActorContext<HttpServerMessages.Message> ctx) {
		return msg -> {
			ctx.getLog().info("Server online at http://{}:{}", msg.binding.localAddress().getAddress(),
					msg.binding.localAddress().getPort());

			return running(msg.binding);
		};
	}

	private Behavior<HttpServerMessages.Message> running(ServerBinding binding) {
		return BehaviorBuilder.<HttpServerMessages.Message>create()
				.onMessage(HttpServerMessages.Stop.class, msg -> Behaviors.stopped()).onSignal(PostStop.class, msg -> {
					binding.unbind();
					return Behaviors.same();
				}).build();
	}

	private void exitIfSystemIsNull() {
		if (this.actorSystem == null) {
			System.out.println("Error: system is null");
			System.exit(1);
		}
	}

}
