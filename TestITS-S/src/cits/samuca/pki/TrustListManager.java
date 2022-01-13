package cits.samuca.pki;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.TlmEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedTlmCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;

import cits.samuca.pki.certificates.TrustListManagerCertificate;
import cits.samuca.utils.Constants;
import cits.samuca.utils.GenericCreationUtils;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

public class TrustListManager {

	private TrustListManagerCertificate trustListManagerCertificate;

	private EtsiTs103097Certificate rootCaCertificate;

	static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

	public TrustListManager() {

		this.trustListManagerCertificate = new TrustListManagerCertificate();

		ToBeSignedTlmCtl toBeSignedEctl = generateEctlRequest();

		final Time64 signingGenerationTime = new Time64(new Date());

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.trustListManagerCertificate.getCertificate(), this.rootCaCertificate };

		final PrivateKey signerPrivateKey = this.trustListManagerCertificate.getSigningKeys().getPrivate();

		final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
				.getMessagesCaGenerator();

		EtsiTs103097DataSigned certificateTrustListMessage = createTrustListManagerCertificate(toBeSignedEctl,
				signingGenerationTime, signerCertificateChain, signerPrivateKey, messagesCaGenerator);

		IOUtils.writeCtlToFile(certificateTrustListMessage, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE);
		IOUtils.writeCtlToFile(certificateTrustListMessage, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE_FOR_COHDA);
		Logger.shortPrint("[root CA         ] ECTL written to file");
	}

	private EtsiTs103097DataSigned createTrustListManagerCertificate(ToBeSignedTlmCtl toBeSignedEctl,
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

		final Url CpocAccessPoint = GenericCreationUtils.createUrl("http://localhost:8080/samuCA/CPOC/dummy");
//
//		HashedId8[] certificateDigests = { new HashedId8(this.rootCaCertificate.getCertificate().getEncoded()) };

		final CtlCommand[] ctlCommands = new CtlCommand[] { //
				new CtlCommand(new CtlEntry(
						new TlmEntry(this.trustListManagerCertificate.getCertificate(), null, CpocAccessPoint))),
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

	public void setRootCaCertificate(EtsiTs103097Certificate rootCaCertificate) {
		this.rootCaCertificate = rootCaCertificate;
	}

}
