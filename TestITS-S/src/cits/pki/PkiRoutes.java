package cits.pki;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import akka.actor.typed.ActorSystem;
import akka.http.javadsl.model.ContentType;
import akka.http.javadsl.model.HttpCharsets;
import akka.http.javadsl.model.HttpEntities;
import akka.http.javadsl.model.HttpEntity;
import akka.http.javadsl.model.HttpEntity.Strict;
import akka.http.javadsl.model.MediaType;
import akka.http.javadsl.model.MediaTypes;
import akka.http.javadsl.model.StatusCodes;
import akka.http.javadsl.server.ExceptionHandler;
import akka.http.javadsl.server.PathMatchers;
import akka.http.javadsl.server.Route;
import akka.http.javadsl.unmarshalling.Unmarshaller;
import scala.concurrent.duration.FiniteDuration;

import static akka.http.javadsl.server.Directives.*;

/**
 * Routes for use with the HttpServerWithActorsSample
 */
public class PkiRoutes {
	private final ActorSystem<HttpPki.Message> system;
	private final ExceptionHandler exceptionHandler;
	private final PKIEntities pkiEntities;

	public PkiRoutes(PKIEntities pki, ActorSystem<HttpPki.Message> sys) {
		this.exceptionHandler = getExceptionHandler();
		this.pkiEntities = pki;
		this.system = sys;
	}

	public Route createRoutes() {
		final FiniteDuration threeSecondsTimeout = createThreeSecondsTimeout();

		Supplier<Route> routesWithExceptionHandling = createRoutesWithExceptionHandling();

		Route rootOfTheRoutes = toStrictEntity(threeSecondsTimeout, routesWithExceptionHandling);

		return rootOfTheRoutes;
	}

	private Supplier<Route> createRoutesWithExceptionHandling() {
		Supplier<Route> innerRoutesWithExceptionHandling = () -> handleExceptions(this.exceptionHandler,
				() -> createRoutesForEtsi102941());
		return innerRoutesWithExceptionHandling;
	}

	private Route createRoutesForEtsi102941() {
		return pathPrefix(PathMatchers.segment("samuCA"), () -> {
			Route rootCaRoutes = createRoutesForRootCa();
			Route enrolmentCaRoutes = createRoutesForEnrolmentCa();
			Route authorizationCaRoutes = createRoutesForAuthorizationCa();
			return concat(rootCaRoutes, enrolmentCaRoutes, authorizationCaRoutes);
		});
	}

	private Route createRoutesForRootCa() {
		Route rootCA = path(PathMatchers.segment("rootCA"), () -> {
			System.out.println("rootCA");
			return complete(StatusCodes.OK);
		});
		return rootCA;
	}

	private Route createRoutesForEnrolmentCa() {

		final MediaType.WithFixedCharset applicationCustom = MediaTypes.customWithFixedCharset("application",
				"x-its-response", // The new Media Type name
				HttpCharsets.UTF_8, // The charset used
				new HashMap<>(), // Empty parameters
				false); // No arbitrary subtypes are allowed

		ContentType customContentType = applicationCustom.toContentType();

		byte[] ba1 = new byte[1];

		final FiniteDuration threeSecondsTimeout = createThreeSecondsTimeout();

		Route ecRequest = post(() -> path(PathMatchers.segment("ECRequest"),

				() -> extractStrictEntity(threeSecondsTimeout, entity -> {
					String contentType = entity.getContentType().toString();
					if (contentTypeMatchesXitsRequest(contentType)) {
						byte[] requestBody = extractBinaryBodyFromRequest(entity);
						Ieee1609Dot2Data enrolmentRequestMessage = null;

						try {
							enrolmentRequestMessage = new Ieee1609Dot2Data(requestBody);

							writeEnrolmentRequestMessageToFile(enrolmentRequestMessage);

							byte[] enrolmentResponseMessage = pkiEntities.getEnrolmentResponseFromEnrolmentCa(requestBody);

							return complete(StatusCodes.OK,
									HttpEntities.create(customContentType, enrolmentResponseMessage));
//							String result = (String) Await.result(future, timeout);
						} catch (IOException | MessageParsingException | SignatureVerificationException
								| DecryptionFailedException | InternalErrorException | GeneralSecurityException e1) {

							System.out.println("exception: " + e1);
							e1.printStackTrace();
						}

						System.out.println("quiquiquiquqiququiqui");
						return complete(StatusCodes.OK, HttpEntities.create(customContentType, ba1));
					}

					return complete(StatusCodes.BAD_REQUEST);
				})));

		Route atRequest = post(() -> path(PathMatchers.segment("ATRequest"), () -> extractRequestEntity(entity -> {
			String contentType = entity.getContentType().toString();
			System.out.println(contentType);
			if (contentTypeMatchesXitsRequest(contentType)) {
				return complete(StatusCodes.OK);
			}
			return complete(StatusCodes.BAD_REQUEST);
		})));

		Route enrolmentCA = pathPrefix(PathMatchers.segment("enrolmentCA"), () -> concat(ecRequest, atRequest));

		return enrolmentCA;
	}

	private void writeEnrolmentRequestMessageToFile(Ieee1609Dot2Data enrolmentRequestMessage) {
		String filename = "test_recv.coer";
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(filename);
			fileOutputStream.write(enrolmentRequestMessage.getEncoded());
			fileOutputStream.close();
		} catch (Exception e) {
			System.out.println("exception: " + e);
		}
	}

	private FiniteDuration createThreeSecondsTimeout() {
		final FiniteDuration timeout = FiniteDuration.create(3, TimeUnit.SECONDS);
		return timeout;
	}

	private byte[] extractBinaryBodyFromRequest(Strict entity) {
		Unmarshaller<HttpEntity, byte[]> unmarshaller = Unmarshaller.entityToByteArray();
		CompletionStage<byte[]> res = unmarshaller.unmarshal(entity, system);

		byte[] request = null;
		try {
			request = res.toCompletableFuture().get();
		} catch (InterruptedException | ExecutionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("recv size: " + request.length);
		return request;
	}

	private boolean contentTypeMatchesXitsRequest(String contentType) {
		return contentType.equals("application/x-its-request");
	}

	private Route createRoutesForAuthorizationCa() {

		Route atRequest = post(() -> path(PathMatchers.segment("ATRequest"), () -> extractEntity(entity -> {
			String contentType = entity.getContentType().toString();
			System.out.println(contentType);
			if (contentTypeMatchesXitsRequest(contentType)) {
				return complete(StatusCodes.OK);
			}
			return complete(StatusCodes.BAD_REQUEST);
		})));

		Route atRequestWithPop = post(
				() -> path(PathMatchers.segment("ATRequestWithPoP"), () -> extractRequestEntity(entity -> {
					String contentType = entity.getContentType().toString();
					System.out.println(contentType);
					if (contentTypeMatchesXitsRequest(contentType)) {
						return complete(StatusCodes.OK);
					}
					return complete(StatusCodes.BAD_REQUEST);
				})));

		Route authorizationCA = pathPrefix(PathMatchers.segment("authorizationCA"),
				() -> concat(atRequest, atRequestWithPop));

		return authorizationCA;
	}

	private ExceptionHandler getExceptionHandler() {
		return ExceptionHandler.newBuilder().matchAny(x -> {
			System.out.println("Exception - check why: " + x);
			// TODO: do something
			return complete(StatusCodes.ENHANCE_YOUR_CALM);
		}).build();
	}

//	private CompletionStage<Optional<JobRepository.Job>> onEnroll() {
//		System.out.println("enroll");
//		return AskPattern.ask(buildJobRepository, replyTo -> new JobRepository.GetJobById(new Long (1), replyTo),
//				Duration.ofSeconds(3), system.scheduler());
//	}

//	private Route onEnroll() {
//		System.out.println("enroll");
//		return concat(
//				post(() -> entity(Jackson.unmarshaller(JobRepository.Job.class),
//						job -> onSuccess(add(job), r -> complete("Job added")))),
//				delete(() -> onSuccess(deleteAll(), r -> complete("Jobs cleared"))));
//	}

	private Route onEnroll() {
		System.out.println("enroll");
		return complete("Enrolled.");
	}

//	private Route onGetCtl() {
//		System.out.println("received request for CTL");
//		final Duration t = Duration.ofSeconds(5);
//		RootCA.GetCtl request = new RootCA.GetCtl();
//
////		CompletableFuture<Object> future = ask(this.rootCA., request, t).toCompletableFuture();
//		return complete("CTL: ");
//	}

//	private Route authorize() {
//		System.out.println("authorize");
//		return concat(
//				post(() -> entity(Jackson.unmarshaller(JobRepository.Job.class),
//						job -> onSuccess(add(job), r -> complete("Job added")))),
//				delete(() -> onSuccess(deleteAll(), r -> complete("Jobs cleared"))));
//	}

//	private CompletionStage<Optional<JobRepository.Job>> getJob(Long jobId) {
//		return AskPattern.ask(buildJobRepository, replyTo -> new JobRepository.GetJobById(jobId, replyTo),
//				Duration.ofSeconds(3), system.scheduler());
//	}

//	private CompletionStage<JobRepository.OK> handleKO(CompletionStage<JobRepository.Response> stage) {
//		return stage.thenApply(response -> {
//			if (response instanceof JobRepository.OK) {
//				return (JobRepository.OK) response;
//			} else if (response instanceof JobRepository.KO) {
//				throw new IllegalStateException(((JobRepository.KO) response).reason);
//			} else {
//				throw new IllegalStateException("Invalid response");
//			}
//		});
//	}
}