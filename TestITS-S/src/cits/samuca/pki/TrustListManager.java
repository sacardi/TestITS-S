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

		setRootCaInformation(rootCaCertificate, rootCaCertificateHashedId8);

		createTrustListManagerCertificate();

		createEuropeanCertificateTrustList();
	}

	private void setRootCaInformation(EtsiTs103097Certificate rootCaCertificate, HashedId8 rootCaCertificateHashedId8) {
		this.rootCaCertificate = rootCaCertificate;
		this.rootCaCertificateHashedId8 = rootCaCertificateHashedId8;
	}

	private void createTrustListManagerCertificate() {
		this.trustListManagerCertificate = new TrustListManagerCertificate();
	}

	private void createEuropeanCertificateTrustList() {
		ToBeSignedTlmCtl toBeSignedEctl = generateInnerEctlRequest();

		signEctl(toBeSignedEctl);
	}

	private void signEctl(ToBeSignedTlmCtl toBeSignedEctl) {
		final Time64 signingGenerationTime = new Time64(new Date());

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.trustListManagerCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.trustListManagerCertificate.getSigningKeys().getPrivate();

		setMessagesCaGenerator();

		EtsiTs103097DataSigned europeanCertificateTrustList = signEctl_exitOnProblems(toBeSignedEctl,
				signingGenerationTime, signerCertificateChain, signerPrivateKey, this.messagesCaGenerator);

		IOUtils.writeCtlToFile(europeanCertificateTrustList, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE);
		IOUtils.writeCtlToFile(europeanCertificateTrustList, Constants.EUROPEAN_CERTIFICATE_TRUST_LIST_FILE_FOR_COHDA);
		Logger.shortPrint("[root CA         ] ECTL written to file");
	}

	private EtsiTs103097DataSigned signEctl_exitOnProblems(ToBeSignedTlmCtl toBeSignedEctl,
			final Time64 signingGenerationTime, final EtsiTs103097Certificate[] signerCertificateChain,
			final PrivateKey signerPrivateKey, final ETSITS102941MessagesCaGenerator messagesCaGenerator) {
		EtsiTs103097DataSigned certificateTrustListMessage = null;

		try {
			certificateTrustListMessage = messagesCaGenerator.genTlmCertificateTrustListMessage(//
					signingGenerationTime, //
					toBeSignedEctl, //
					signerCertificateChain, //
					signerPrivateKey//
			);

		} catch (SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return certificateTrustListMessage;
	}

	private ToBeSignedTlmCtl generateInnerEctlRequest() {
		final Version version = Version.V1;
		final Time32 nextUpdate = GenericCreationUtils.createNextUpdateThisDateInTheFuture("20250910 14:14:14");
		final boolean isFullCtl = true;
		final int ctlSequence = 0;

		final Url CpocAccessPoint = GenericCreationUtils
				.createUrl("http://" + Constants.IP_ADDRESS + ":8080/samuCA/CPOC/");

		final Url dcAccessPoint = GenericCreationUtils.createUrl("http://" + Constants.IP_ADDRESS + ":8080/samuCA/DC");

		HashedId8[] digestsOfTrustedCertificates = { this.rootCaCertificateHashedId8 };

		RootCaEntry rootCaEntry = new RootCaEntry(this.rootCaCertificate, null);
		DcEntry dcEntry = new DcEntry(dcAccessPoint, new SequenceOfHashedId8(digestsOfTrustedCertificates));
		TlmEntry tlmEntry = new TlmEntry(this.trustListManagerCertificate.getCertificate(), null, CpocAccessPoint);
		final CtlCommand[] ctlCommands = new CtlCommand[] { //
				new CtlCommand(new CtlEntry(rootCaEntry)), //
				new CtlCommand(new CtlEntry(dcEntry)), //
				new CtlCommand(new CtlEntry(tlmEntry)), //
		};

		return new ToBeSignedTlmCtl( //
				version, //
				nextUpdate, //
				isFullCtl, //
				ctlSequence, //
				ctlCommands);
	}

	private void setMessagesCaGenerator() {

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
