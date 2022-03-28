package cits.samuca.httpserver;

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
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
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
import cits.samuca.pki.PKIEntities;
import cits.samuca.utils.Constants;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.PkiUtilsSingleton;
import scala.concurrent.duration.FiniteDuration;

import static akka.http.javadsl.server.Directives.*;

public class PkiRoutes {
	private final ActorSystem<HttpServerMessages.Message> system;
	private final ExceptionHandler exceptionHandler;
	private final PKIEntities pkiEntities;

	public PkiRoutes(PKIEntities pki, ActorSystem<HttpServerMessages.Message> sys) {
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
				() -> createRoutesForEtsi102941Requests());
		return innerRoutesWithExceptionHandling;
	}

	private Route createRoutesForEtsi102941Requests() {
		return pathPrefix(PathMatchers.segment("samuCA"), () -> {
			Route rootCaRoutes = createRoutesForRootCa();
			Route enrolmentCaRoutes = createRoutesForEnrolmentCa();
			Route authorizationCaRoutes = createRoutesForAuthorizationCa();
			Route distributionCenterRoutes = createRoutesForDistributionCenter();
			return concat(rootCaRoutes, enrolmentCaRoutes, authorizationCaRoutes, distributionCenterRoutes);
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

		Route ecRequest = post(() -> path(PathMatchers.segment("enrolment"),

				() -> extractStrictEntity(threeSecondsTimeout, entity -> {
					String contentType = entity.getContentType().toString();
					if (contentTypeMatchesXitsRequest(contentType)) {
						byte[] requestBody = extractBinaryBodyFromRequest(entity);
						Ieee1609Dot2Data enrolmentRequestMessage = null;

						try {
							enrolmentRequestMessage = new Ieee1609Dot2Data(requestBody);

							writeEnrolmentRequestMessageToFile(enrolmentRequestMessage);

							byte[] enrolmentResponseMessage = pkiEntities
									.getEnrolmentResponseFromEnrolmentCa(requestBody);

							return complete(StatusCodes.OK,
									HttpEntities.create(customContentType, enrolmentResponseMessage));
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

	private Route createRoutesForDistributionCenter() {

		Route getCtl = createRouteForCtl();

		Route getCrl = createRouteForCrl();

		Route getEctl = createRouteForEctl();

		Route distributionCenter = pathPrefix(PathMatchers.segment("DC"), () -> concat(getCtl, getCrl, getEctl));

		return distributionCenter;
	}

	private Route createRouteForCtl() {
		final MediaType.WithFixedCharset applicationCustom = MediaTypes.customWithFixedCharset("application",
				"x-its-ctl", // The new Media Type name
				HttpCharsets.UTF_8, // The charset used
				new HashMap<>(), // Empty parameters
				false); // No arbitrary subtypes are allowed

		ContentType customContentType = applicationCustom.toContentType();

		Route getCtl = get(() -> path(PathMatchers.segment("getctl"),

				() -> {
					System.out.println("getCTL");

					EtsiTs103097DataSigned ctl = IOUtils.readCtlFromFile(Constants.CERTIFICATE_TRUST_LIST_FILE);

					byte[] encodedCtl = null;
					try {
						encodedCtl = ctl.getEncoded();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						System.exit(1);
					}

					return complete(StatusCodes.OK, HttpEntities.create(customContentType, encodedCtl));
				}));

		return getCtl;
	}

	private Route createRouteForCrl() {
		final MediaType.WithFixedCharset applicationCustom = MediaTypes.customWithFixedCharset("application",
				"x-its-crl", // The new Media Type name
				HttpCharsets.UTF_8, // The charset used
				new HashMap<>(), // Empty parameters
				false); // No arbitrary subtypes are allowed

		ContentType customContentType = applicationCustom.toContentType();

		Route getCrl = get(() -> path(PathMatchers.segment("getcrl"),

				() -> {
					System.out.println("getCRL");

					EtsiTs103097DataSigned crl = IOUtils.readCrlFromFile(Constants.CERTIFICATE_REVOCATION_LIST_FILE);

					byte[] encodedCrl = null;
					try {
						encodedCrl = crl.getEncoded();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						System.exit(1);
					}

					return complete(StatusCodes.OK, HttpEntities.create(customContentType, encodedCrl));
				}));
		return getCrl;
	}

	private Route createRouteForEctl() {
		final MediaType.WithFixedCharset applicationCustom = MediaTypes.customWithFixedCharset("application",
				"x-its-ectl", // The new Media Type name
				HttpCharsets.UTF_8, // The charset used
				new HashMap<>(), // Empty parameters
				false); // No arbitrary subtypes are allowed

		ContentType customContentType = applicationCustom.toContentType();

		Route getCrl = get(() -> path(PathMatchers.segment("getectl"),

				() -> {
					System.out.println("getECTL");

					EtsiTs103097DataSigned ectl = IOUtils.readCtlFromFile(Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE);

					byte[] encodedEctl = null;
					try {
						encodedEctl = ectl.getEncoded();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						System.exit(1);
					}

					return complete(StatusCodes.OK, HttpEntities.create(customContentType, encodedEctl));
				}));
		return getCrl;
	}

	private ExceptionHandler getExceptionHandler() {
		return ExceptionHandler.newBuilder().matchAny(x -> {
			System.out.println("Exception - check why: " + x);
			// TODO: do something
			return complete(StatusCodes.ENHANCE_YOUR_CALM);
		}).build();
	}

}