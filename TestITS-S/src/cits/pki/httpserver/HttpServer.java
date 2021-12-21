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
import cits.pki.httpserver.HttpServerMessages.Message;
import akka.actor.typed.ActorSystem;

public class HttpServer {

	private ActorSystem<HttpServerMessages.Message> system;
	private PKIEntities pki;

	private String address = "localhost";
	private Integer port = 8080;

	public HttpServer(PKIEntities pki) {
		this.pki = pki;

		createActorSystem();
	}

	private void createActorSystem() {
		this.system = ActorSystem.create(startServer(), "SamuPkiActorSystem");

		exitIfSystemIsNull();
	}

	public Behavior<HttpServerMessages.Message> startServer() {
		return Behaviors.setup(ctx -> {

			Route httpRoutes = createHttpRoutes();

			startServerWithCustomHttpRoutes(ctx, httpRoutes);

			return starting(false);
		});
	}

	private void startServerWithCustomHttpRoutes(ActorContext<Message> ctx, Route httpRoutes) {
		CompletionStage<ServerBinding> serverBinding = bindServer(httpRoutes);

		ifBindingWasSuccessfulSendServerBindingMessageToSelf(ctx, serverBinding);
	}

	private void exitIfSystemIsNull() {
		if (this.system == null) {
			System.out.println("Error: system is null");
			System.exit(1);
		}
	}

	public void ifBindingWasSuccessfulSendServerBindingMessageToSelf(ActorContext<HttpServerMessages.Message> ctx,
			CompletionStage<ServerBinding> serverBinding) {

		ctx.pipeToSelf(serverBinding, (binding, failure) -> {
			if (binding != null)
				return new HttpServerMessages.Started(binding);
			else
				return new HttpServerMessages.StartFailed(failure);
		});
	}

	private CompletionStage<ServerBinding> bindServer(Route routes) {
		CompletionStage<ServerBinding> serverBinding = Http.get(system).newServerAt(this.address, this.port)
				.bind(routes);
		return serverBinding;
	}

	private Route createHttpRoutes() {
		Route routes = new PkiRoutes(pki, system).createRoutes();
		return routes;
	}

	private Behavior<HttpServerMessages.Message> starting(boolean wasStopped) {
		return Behaviors.setup(ctx -> createMessageHandlers(wasStopped, ctx));
	}

	private Behavior<HttpServerMessages.Message> createMessageHandlers(boolean wasStopped,
			ActorContext<HttpServerMessages.Message> ctx) {
		return BehaviorBuilder.<HttpServerMessages.Message>create()
				.onMessage(HttpServerMessages.StartFailed.class, handleStartFailedMessage())
				.onMessage(HttpServerMessages.Started.class, handleStartedMessage(wasStopped, ctx))
				.onMessage(HttpServerMessages.Stop.class, handleStopMessage()).build();
	}

	private Function<HttpServerMessages.StartFailed, Behavior<HttpServerMessages.Message>> handleStartFailedMessage() {
		return failed -> {
			throw new RuntimeException("Server failed to start", failed.ex);
		};
	}

	private Function<HttpServerMessages.Stop, Behavior<HttpServerMessages.Message>> handleStopMessage() {
		return s -> {
			// we got a stop message but haven't completed starting yet,
			// we cannot stop until starting has completed
			return starting(true);
		};
	}

	private Function<HttpServerMessages.Started, Behavior<HttpServerMessages.Message>> handleStartedMessage(
			boolean wasStopped, ActorContext<HttpServerMessages.Message> ctx) {
		return msg -> {
			ctx.getLog().info("Server online at http://{}:{}", msg.binding.localAddress().getAddress(),
					msg.binding.localAddress().getPort());

			if (wasStopped)
				ctx.getSelf().tell(new HttpServerMessages.Stop());

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

}