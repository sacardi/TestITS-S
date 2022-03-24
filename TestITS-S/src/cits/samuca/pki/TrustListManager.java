package cits.samuca.pki;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.DcEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.RootCaEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.TlmEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedTlmCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import cits.samuca.pki.certificates.TrustListManagerCertificate;
import cits.samuca.utils.Constants;
import cits.samuca.utils.GenericCreationUtils;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

public class TrustListManager {

	private TrustListManagerCertificate trustListManagerCertificate;

	private EtsiTs103097Certificate rootCaCertificate;

	private HashedId8 rootCaCertificateHashedId8;

	private DefaultCryptoManager cryptoManager;

	private ETSITS102941MessagesCaGenerator messagesCaGenerator;

	static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

	public TrustListManager(EtsiTs103097Certificate rootCaCertificate, HashedId8 rootCaCertificateHashedId8) {

		this.rootCaCertificate = rootCaCertificate;
		this.rootCaCertificateHashedId8 = rootCaCertificateHashedId8;

		this.trustListManagerCertificate = new TrustListManagerCertificate();

		ToBeSignedTlmCtl toBeSignedEctl = generateEctlRequest();

		final Time64 signingGenerationTime = new Time64(new Date());

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.trustListManagerCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.trustListManagerCertificate.getSigningKeys().getPrivate();

//		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
//				.getMessagesCaGenerator();
		
		setCaMessagesGenerator();

		EtsiTs103097DataSigned europeanCertificateTrustList = createEuropeanCertificateTrustList(toBeSignedEctl,
				signingGenerationTime, signerCertificateChain, signerPrivateKey, messagesCaGenerator);

		IOUtils.writeCtlToFile(europeanCertificateTrustList, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE);
		IOUtils.writeCtlToFile(europeanCertificateTrustList, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE_FOR_COHDA);
		Logger.shortPrint("[root CA         ] ECTL written to file");
	}

	private EtsiTs103097DataSigned createEuropeanCertificateTrustList(ToBeSignedTlmCtl toBeSignedEctl,
			final Time64 signingGenerationTime, final EtsiTs103097Certificate[] signerCertificateChain,
			final PrivateKey signerPrivateKey, final ETSITS102941MessagesCaGenerator messagesCaGenerator) {
		EtsiTs103097DataSigned certificateTrustListMessage = null;

		try {
			certificateTrustListMessage = messagesCaGenerator.genTlmCertificateTrustListMessage(//
					signingGenerationTime, //
					toBeSignedEctl, //
					signerCertificateChain, //
					signerPrivateKey);

		} catch (SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return certificateTrustListMessage;
	}

	private ToBeSignedTlmCtl generateEctlRequest() {
		final Version version = Version.V1;
		final Time32 nextUpdate = GenericCreationUtils.createNextUpdateThisDateInTheFuture("20250910 14:14:14");
		final boolean isFullCtl = true;
		final int ctlSequence = 0;

//		final Url itsAccessPoint = new Url("http://localhost:8080/samuCA/itss/dummy");
//		final Url eaAccessPoint = new Url("http://localhost:8080/samuCA/enrolmentCA/");
//		final Url aaAccessPoint = new Url("http://localhost:8080/samuCA/authorizationCA");
//		final Url dcAccessPoint = new Url("http://localhost:8080/samuCA/dummy");

		final Url CpocAccessPoint = GenericCreationUtils
				.createUrl("http://" + Constants.IP_ADDRESS + ":8080/samuCA/CPOC/dummy");
//
//		HashedId8[] certificateDigests = { new HashedId8(this.rootCaCertificate.getCertificate().getEncoded()) };

		final Url dcAccessPoint = GenericCreationUtils
				.createUrl("http://" + Constants.IP_ADDRESS + ":8080/samuCA/dummy");
		final HashedId8 rootCaEncodedCertificate = this.rootCaCertificateHashedId8;
		HashedId8[] digestsOfTrustedCertificates = { rootCaEncodedCertificate };

		final CtlCommand[] ctlCommands = new CtlCommand[] { //
				new CtlCommand(new CtlEntry(new RootCaEntry(this.rootCaCertificate, null))), //
				new CtlCommand(new CtlEntry(
						new DcEntry(dcAccessPoint, new SequenceOfHashedId8(digestsOfTrustedCertificates)))), //
				new CtlCommand(new CtlEntry(
						new TlmEntry(this.trustListManagerCertificate.getCertificate(), null, CpocAccessPoint))), //
//				new CtlCommand(new CtlEntry(
//						new EaEntry(this.enrolmentCaCertificate.getCertificate(), eaAccessPoint, itsAccessPoint))), //
//				new CtlCommand(
//						new CtlEntry(new AaEntry(this.authorizationCaCertificate.getCertificate(), aaAccessPoint))), //
//				new CtlCommand(new CtlEntry(new DcEntry(dcAccessPoint, new SequenceOfHashedId8(certificateDigests)))), //
		};

		return new ToBeSignedTlmCtl( //
				version, //
				nextUpdate, //
				isFullCtl, //
				ctlSequence, //
				ctlCommands);
	}

	private void setCaMessagesGenerator() {
		
		setCryptoManager();

		int versionToGenerate = Ieee1609Dot2Data.DEFAULT_VERSION;
		HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
		SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaBrainpoolP256r1Signature;

		try {
			this.messagesCaGenerator = new ETSITS102941MessagesCaGenerator( //
					versionToGenerate, //
					this.cryptoManager, //
					digestAlgorithm, //
					signatureScheme);

		} catch (SignatureException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void setCryptoManager() {

		this.cryptoManager = new DefaultCryptoManager();

		try {
			this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

		} catch (IllegalArgumentException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| IOException | BadCredentialsException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}
