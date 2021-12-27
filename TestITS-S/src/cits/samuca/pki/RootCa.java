package cits.samuca.pki;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.AaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CrlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.DcEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedRcaCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import cits.samuca.utils.Logger;
import cits.samuca.pki.certificates.AuthorizationCaCertificate;
import cits.samuca.pki.certificates.EnrolmentCaCertificate;
import cits.samuca.pki.certificates.RootCaCertificate;
import cits.samuca.utils.IOUtils;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;

public class RootCa {
	public static final int port = 8886;

	private Ieee1609Dot2CryptoManager cryptoManager;

	private ETSITS102941MessagesCaGenerator messagesCaGenerator = null;

	private RootCaCertificate rootCaCertificate;

	private EnrolmentCaCertificate enrolmentCaCertificate;

	private AuthorizationCaCertificate authorizationCaCertificate;

	public RootCa() throws Exception {

		createCertificatesAndKeyPairsForAllAuthorities();

		generateCTL();

		generateCRL();
	}

	private void createCertificatesAndKeyPairsForAllAuthorities()
			throws SignatureException, IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException, ClassNotFoundException {

		this.rootCaCertificate = new RootCaCertificate();

		this.enrolmentCaCertificate = new EnrolmentCaCertificate(//
				this.rootCaCertificate.getCertificate(), //
				this.rootCaCertificate.getSigningKeys());

		this.authorizationCaCertificate = new AuthorizationCaCertificate(//
				this.rootCaCertificate.getCertificate(), //
				this.rootCaCertificate.getSigningKeys());
	}

	static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

	private void generateCTL() throws Exception {

		setupCryptoManager();

		ToBeSignedRcaCtl toBeSignedCtl = generateCtlRequest();

		setCaMessagesGenerator();
		final Time64 signingGenerationTime = new Time64(new Date());

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.rootCaCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.rootCaCertificate.getSigningKeys().getPrivate();

		EtsiTs103097DataSigned certificateTrustListMessage = this.messagesCaGenerator.genRcaCertificateTrustListMessage(//
				signingGenerationTime, //
				toBeSignedCtl, //
				signerCertificateChain, //
				signerPrivateKey);

		IOUtils.writeCtlToFile(certificateTrustListMessage, "CTL.coer");
		Logger.shortPrint("[root CA         ] CTL written to file");

	}

	private ToBeSignedRcaCtl generateCtlRequest() throws Exception {
		final Version version = Version.V1;
		final Time32 nextUpdate = new Time32(dateFormat.parse("20250910 14:14:14"));
		final boolean isFullCtl = true;
		final int ctlSequence = 0;

		final Url itsAccessPoint = new Url("http://localhost:8080/samuCA/itss/dummy");
		final Url eaAccessPoint = new Url("http://localhost:8080/samuCA/enrolmentCA/");
		final Url aaAccessPoint = new Url("http://localhost:8080/samuCA/authorizationCA");
		final Url dcAccessPoint = new Url("http://localhost:8080/samuCA/dummy");

		HashedId8[] certificateDigests = { new HashedId8(this.rootCaCertificate.getCertificate().getEncoded()) };

		final CtlCommand[] ctlCommands = new CtlCommand[] { //
				new CtlCommand(new CtlEntry(
						new EaEntry(this.enrolmentCaCertificate.getCertificate(), eaAccessPoint, itsAccessPoint))), //
				new CtlCommand(
						new CtlEntry(new AaEntry(this.authorizationCaCertificate.getCertificate(), aaAccessPoint))), //
				new CtlCommand(new CtlEntry(new DcEntry(dcAccessPoint, new SequenceOfHashedId8(certificateDigests)))), //
		};

		return new ToBeSignedRcaCtl( //
				version, //
				nextUpdate, //
				isFullCtl, //
				ctlSequence, //
				ctlCommands);
	}

	private void generateCRL() throws SignatureException, IOException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException, ParseException {

		setupCryptoManager();

		ToBeSignedCrl toBeSignedCrl = generateCrlRequest();

		setCaMessagesGenerator();

		final Time64 signingGenerationTime = new Time64(new Date());

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.rootCaCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.rootCaCertificate.getSigningKeys().getPrivate();

		EtsiTs103097DataSigned certificateRevocationListMessage = this.messagesCaGenerator
				.genCertificateRevocationListMessage(//
						signingGenerationTime, //
						toBeSignedCrl, //
						signerCertificateChain, //
						signerPrivateKey);

//        // To verify CTL and CRL messages
//        Map<HashedId8, Certificate> crlTrustStore = new HashMap<>(); // Only root ca needed from truststore in this case.
//        VerifyResult<ToBeSignedCrl> crlVerifyResult = messagesCaGenerator.verifyCertificateRevocationListMessage(
//                certificateRevocationListMessage,
//                crlTrustStore,
//                trustStore
//        );

		IOUtils.writeCrlToFile(certificateRevocationListMessage, "CRL.coer");
		Logger.shortPrint("[root CA         ] CRL written to file");
	}

	private ToBeSignedCrl generateCrlRequest() throws ParseException {
		final Version version = Version.V1;

		Time32 thisUpdate = new Time32(new Date());

		final Time32 nextUpdate = new Time32(dateFormat.parse("20250910 14:14:14"));

		final CrlEntry[] emptyCrl = new CrlEntry[] {};

		return new ToBeSignedCrl(version, //
				thisUpdate, //
				nextUpdate, //
				emptyCrl);
	}

	private void setupCryptoManager() throws IllegalArgumentException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException, BadCredentialsException {

		if (this.cryptoManager != null) {
			return;
		}

		this.cryptoManager = new DefaultCryptoManager();
		this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	}

	private void setCaMessagesGenerator() throws SignatureException {
		if (this.messagesCaGenerator != null) {
			return;
		}
		int versionToGenerate = Ieee1609Dot2Data.DEFAULT_VERSION;
		HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
		SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaNistP256Signature;

		this.messagesCaGenerator = new ETSITS102941MessagesCaGenerator( //
				versionToGenerate, //
				this.cryptoManager, //
				digestAlgorithm, //
				signatureScheme);
	}

	public EtsiTs103097Certificate getRootCaCertificate() {
		return this.rootCaCertificate.getCertificate();
	}

	public EtsiTs103097Certificate getEnrolmentCaCertificate() {
		return this.enrolmentCaCertificate.getCertificate();
	}

	public KeyPair getEnrolmentCaSigningKeys() {
		return this.enrolmentCaCertificate.getSigningKeys();
	}

	public KeyPair getEnrolmentCaEncryptionKeys() {
		return this.enrolmentCaCertificate.getEncryptionKeys();
	}

	public EtsiTs103097Certificate[] getEnrolmentCaChain() {
		return this.enrolmentCaCertificate.getCaChain();
	}

	public EtsiTs103097Certificate getAuthorizationCaCertificate() {
		return this.authorizationCaCertificate.getCertificate();
	}

	public KeyPair getAuthorizationCaSigningKeys() {
		return this.authorizationCaCertificate.getSigningKeys();
	}

	public KeyPair getAuthorizationCaEncryptionKeys() {
		return this.authorizationCaCertificate.getEncryptionKeys();
	}

	public EtsiTs103097Certificate[] getAuthorizationCaChain() {
		return this.authorizationCaCertificate.getCaChain();
	}
}
