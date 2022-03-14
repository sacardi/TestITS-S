package cits.samuca.pki;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Date;

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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;

import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;
import cits.samuca.pki.certificates.AuthorizationCaCertificate;
import cits.samuca.pki.certificates.EnrolmentCaCertificate;
import cits.samuca.pki.certificates.RootCaCertificate;
import cits.samuca.utils.Constants;
import cits.samuca.utils.GenericCreationUtils;
import cits.samuca.utils.IOUtils;

public class RootCa {

	private RootCaCertificate rootCaCertificate;

	private EnrolmentCaCertificate enrolmentCaCertificate;

	private AuthorizationCaCertificate authorizationCaCertificate;

	public RootCa() {

		createCertificatesAndKeyPairsForAllAuthorities();

		generateCertificateTrustList();

		generateCertificateRevocationList();
	}

	private void createCertificatesAndKeyPairsForAllAuthorities() {

		this.rootCaCertificate = new RootCaCertificate();

		this.enrolmentCaCertificate = new EnrolmentCaCertificate(//
				this.rootCaCertificate.getCertificate(), //
				this.rootCaCertificate.getSigningKeys());

		this.authorizationCaCertificate = new AuthorizationCaCertificate(//
				this.rootCaCertificate.getCertificate(), //
				this.rootCaCertificate.getSigningKeys());
	}

	private void generateCertificateTrustList() {

		ToBeSignedRcaCtl toBeSignedCtl = generateInnerCertificateTrustList();

		EtsiTs103097DataSigned certificateTrustList = signInnerCertificateTrustList(toBeSignedCtl);

		IOUtils.writeCtlToFile(certificateTrustList, Constants.CERTIFICATE_TRUST_LIST_FILE);
		IOUtils.writeCtlToFile(certificateTrustList, Constants.CERTIFICATE_TRUST_LIST_FILE_FOR_COHDA);

		Logger.shortPrint("[root CA         ] CTL written to file");
	}

	private ToBeSignedRcaCtl generateInnerCertificateTrustList() {
		final Version version = Version.V1;
		Time32 nextUpdate = GenericCreationUtils.createNextUpdateThisDateInTheFuture("20250910 14:14:14");
		final boolean isFullCtl = true;
		final int ctlSequence = 0;

		final Url itsAccessPoint = GenericCreationUtils.createUrl("http://localhost:8080/samuCA/itss/dummy");
		final Url eaAccessPoint = GenericCreationUtils.createUrl("http://localhost:8080/samuCA/enrolmentCA/");
		final Url aaAccessPoint = GenericCreationUtils.createUrl("http://localhost:8080/samuCA/authorizationCA");
		final Url dcAccessPoint = GenericCreationUtils.createUrl("http://localhost:8080/samuCA/dummy");

		final HashedId8 rootCaEncodedCertificate = this.rootCaCertificate.getCertificateHashedId8();
		HashedId8[] digestsOfTrustedCertificates = { rootCaEncodedCertificate };

		final CtlCommand[] ctlCommands = new CtlCommand[] { //
				new CtlCommand(new CtlEntry(
						new EaEntry(this.enrolmentCaCertificate.getCertificate(), eaAccessPoint, itsAccessPoint))), //
				new CtlCommand(
						new CtlEntry(new AaEntry(this.authorizationCaCertificate.getCertificate(), aaAccessPoint))), //
				new CtlCommand(new CtlEntry(
						new DcEntry(dcAccessPoint, new SequenceOfHashedId8(digestsOfTrustedCertificates)))), //
		};

		return new ToBeSignedRcaCtl( //
				version, //
				nextUpdate, //
				isFullCtl, //
				ctlSequence, //
				ctlCommands);
	}

	private EtsiTs103097DataSigned signInnerCertificateTrustList(ToBeSignedRcaCtl toBeSignedCtl) {

		final Date now = new Date();
		final Time64 signingGenerationTime = new Time64(now);

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.rootCaCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.rootCaCertificate.getSigningKeys().getPrivate();

		EtsiTs103097DataSigned certificateTrustList = signInnerCtl_exitOnProblems(//
				toBeSignedCtl, //
				signingGenerationTime, //
				signerCertificateChain, //
				signerPrivateKey);

		return certificateTrustList;
	}

	private EtsiTs103097DataSigned signInnerCtl_exitOnProblems(ToBeSignedRcaCtl toBeSignedCtl,
			final Time64 signingGenerationTime, final EtsiTs103097Certificate[] signerCertificateChain,
			final PrivateKey signerPrivateKey) {

		EtsiTs103097DataSigned certificateTrustList = null;

		try {
			final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
					.getMessagesCaGenerator();

			certificateTrustList = messagesCaGenerator.genRcaCertificateTrustListMessage(//
					signingGenerationTime, //
					toBeSignedCtl, //
					signerCertificateChain, //
					signerPrivateKey);

		} catch (SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return certificateTrustList;
	}

	private void generateCertificateRevocationList() {

		ToBeSignedCrl toBeSignedCrl = generateInnerCertificateRevocationList();

		EtsiTs103097DataSigned certificateRevocationList = signInnerCertificateRevocationList(toBeSignedCrl);

		IOUtils.writeCrlToFile(certificateRevocationList, Constants.CERTIFICATE_REVOCATION_LIST_FILE);
		IOUtils.writeCrlToFile(certificateRevocationList, Constants.CERTIFICATE_REVOCATION_LIST_FILE_FOR_COHDA);

		Logger.shortPrint("[root CA         ] CRL written to file");
	}

	private ToBeSignedCrl generateInnerCertificateRevocationList() {
		final Version version = Version.V1;

		Time32 thisUpdate = new Time32(new Date());

		final Time32 nextUpdate = GenericCreationUtils.createNextUpdateThisDateInTheFuture("20250910 14:14:14");

		final CrlEntry[] emptyCrl = new CrlEntry[] {};

		return new ToBeSignedCrl(version, //
				thisUpdate, //
				nextUpdate, //
				emptyCrl);
	}

	private EtsiTs103097DataSigned signInnerCertificateRevocationList(ToBeSignedCrl toBeSignedCrl) {
		final Date now = new Date();
		final Time64 signingGenerationTime = new Time64(now);

		final EtsiTs103097Certificate[] signerCertificateChain = new EtsiTs103097Certificate[] {
				this.rootCaCertificate.getCertificate() };

		final PrivateKey signerPrivateKey = this.rootCaCertificate.getSigningKeys().getPrivate();

		EtsiTs103097DataSigned certificateRevocationList = signInnerCrl_exitOnProblems(//
				toBeSignedCrl, //
				signingGenerationTime, //
				signerCertificateChain, //
				signerPrivateKey);

		return certificateRevocationList;
	}

	private EtsiTs103097DataSigned signInnerCrl_exitOnProblems(ToBeSignedCrl toBeSignedCrl,
			final Time64 signingGenerationTime, final EtsiTs103097Certificate[] signerCertificateChain,
			final PrivateKey signerPrivateKey) {

		EtsiTs103097DataSigned signedCrl = null;

		try {
			final ETSITS102941MessagesCaGenerator messagesCaGenerator = PkiUtilsSingleton.getInstance()
					.getMessagesCaGenerator();

			signedCrl = messagesCaGenerator.genCertificateRevocationListMessage(//
					signingGenerationTime, //
					toBeSignedCrl, //
					signerCertificateChain, //
					signerPrivateKey);

		} catch (SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return signedCrl;
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
