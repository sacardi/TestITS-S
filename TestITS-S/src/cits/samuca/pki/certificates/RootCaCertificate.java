package cits.samuca.pki.certificates;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.CertChainBuilder;

import cits.samuca.utils.Constants;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;
import cits.samuca.utils.IOUtils;

public class RootCaCertificate {

	private EtsiTs103097Certificate rootCaCertificate;

	private KeyPair rootCaSigningKeys;

	private KeyPair rootCaEncryptionKeys;

	public RootCaCertificate() {

		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs() {

		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readRootCaCertificateAndKeyPairs();
		} else {
			createRootCaCertificateAndKeyPairs();
		}
	}

	private void createRootCaCertificateAndKeyPairs() {

		createRootCaKeyPairs();

		createRootCaCertificate();
	}

	private void createRootCaCertificate() {

		final long daysOffset = 3;
		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - daysOffset * 24 * 60 * 60 * 1000);
		ValidityPeriod rootCaValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 5);

		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey signingPublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signingPrivateKey = this.rootCaSigningKeys.getPrivate();

		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = null;

		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		// not required, can be null
//		final int confidenceLevel = 2;
//		final SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
		final SubjectAssurance subjectAssurance = null;

		String rootCaName = "samuCA.autostrade.it";
		Hostname rootCaHostname = createHostNameFromString(rootCaName);
		final CertificateId certificateId = new CertificateId(rootCaHostname);

		final PsidSsp[] appPermissions = createAppPermissions();

		final PsidGroupPermissions[] certIssuePermissions = createCertIssuePermission();

		createRootCaCertificate(//
				rootCaValidityPeriod, //
				signingPublicKeyAlgorithm, //
				signingPublicKey, //
				signingPrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey, //
				authorityCertGenerator, //
				geographicRegion, //
				subjectAssurance, //
				certificateId, //
				appPermissions, //
				certIssuePermissions);

		IOUtils.writeCertificateToFile(this.rootCaCertificate, Constants.ROOT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Root CA certificate written to file");
	}

	private PsidSsp[] createAppPermissions() {
		PsidSsp[] appPermissions = null;

		try {
			appPermissions = new PsidSsp[] {
					new PsidSsp(new Psid(622),
							new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.bitmapSsp,
									Hex.decode("01"))),
					new PsidSsp(new Psid(624), new ServiceSpecificPermissions(
							ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("0138"))) };
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return appPermissions;
	}

	private PsidGroupPermissions[] createCertIssuePermission() {
		final PsidGroupPermissions firstPsidGroupPermissions = createFirstSetOfPermissions();

		final PsidGroupPermissions secondPsidGroupPermissions = createSecondSetOfPermissions();

		final PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] { //
				firstPsidGroupPermissions, //
				secondPsidGroupPermissions //
		};
		return certIssuePermissions;
	}

	private PsidGroupPermissions createFirstSetOfPermissions() {
		// According to ITU OER canonical octet encoding rules for DEFAULT items "each
		// component that is marked DEFAULT shall be encoded as absent if its value is
		// identical to the default value."
		// => Exclude all the DEFAULT items (minChainLength /
		// chainLengthRange / EndEntityType) that actually use the default value.
		// This means all occurrences of "minChainLength 1", "chainLengthRange 0"
		// and "eeType '10000000'B".
		int minChainDepth1 = 2;
//		int chainDepthRange1 = 0;

		final boolean appBoolean1 = true;
		final boolean enrollBoolean1 = true;

		EndEntityType eeType1 = new EndEntityType(appBoolean1, enrollBoolean1);

		PsidSspRange psidSspRange36 = new PsidSspRange(new Psid(36), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFC"), Hex.decode("FF0003"))));

		PsidSspRange psidSspRange37 = new PsidSspRange(new Psid(37), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFF"), Hex.decode("FF000000"))));

		PsidSspRange psidSspRange137 = new PsidSspRange(new Psid(137), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01E0"), Hex.decode("FF1F"))));

		PsidSspRange psidSspRange138 = new PsidSspRange(new Psid(138), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));

		PsidSspRange psidSspRange139 = new PsidSspRange(new Psid(139), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFFFFF8"), Hex.decode("FF0000000007"))));

		PsidSspRange psidSspRange140 = new PsidSspRange(new Psid(140), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFE0"), Hex.decode("FF00001F"))));

		PsidSspRange psidSspRange141 = new PsidSspRange(new Psid(141), null);

		PsidSspRange psidSspRange623 = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));

		final PsidGroupPermissions firstPsidGroupPermissions = new PsidGroupPermissions(
				new SubjectPermissions(SubjectPermissionsChoices.explicit, //
						new SequenceOfPsidSspRange(new PsidSspRange[] { //
								psidSspRange36, //
								psidSspRange37, //
//								psidSspRange137, //
//								psidSspRange138, //
								psidSspRange139, //
//								psidSspRange140, //
								psidSspRange141, //
								psidSspRange623 //
						})), //
				minChainDepth1, // minChainDepth1
				null, // chainDepthRange1
				eeType1// eeType1
		);
		return firstPsidGroupPermissions;
	}

	private PsidGroupPermissions createSecondSetOfPermissions() {
		// According to ITU OER canonical octet encoding rules for DEFAULT items "each
		// component that is marked DEFAULT shall be encoded as absent if its value is
		// identical to the default value."
		// => Exclude all the DEFAULT items (minChainLength /
		// chainLengthRange / EndEntityType) that actually use the default value.
		// This means all occurrences of "minChainLength 1", "chainLengthRange 0"
		// and "eeType '10000000'B".

		// int minChainDepth2 = 1;
		// int chainDepthRange2 = 0;

		// final boolean appBoolean2 = true;
		// final boolean enrollBoolean2 = false;

		// EndEntityType eeType2 = new EndEntityType(appBoolean2, enrollBoolean2);

		PsidSspRange sixthPsidSspRange = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("013E"), Hex.decode("FFC1"))));

		final PsidGroupPermissions secondPsidGroupPermissions = new PsidGroupPermissions(
				new SubjectPermissions(SubjectPermissionsChoices.explicit, //
						new SequenceOfPsidSspRange(new PsidSspRange[] { //
								sixthPsidSspRange //
						})), //
				null, // minChainDepth2
				null, // chainDepthRange2
				null // eeType2
		);
		return secondPsidGroupPermissions;
	}

	private void createRootCaCertificate(ValidityPeriod rootCaValidityPeriod,
			SignatureChoices signingPublicKeyAlgorithm, PublicKey signingPublicKey, PrivateKey signingPrivateKey,
			SymmAlgorithm symmetricEncryptionAlgorithm, BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm,
			PublicKey encryptionPublicKey, ETSIAuthorityCertGenerator authorityCertGenerator,
			GeographicRegion geographicRegion, final SubjectAssurance subjectAssurance,
			final CertificateId certificateId, final PsidSsp[] appPermissions,
			final PsidGroupPermissions[] certIssuePermissions) {
		try {
			this.rootCaCertificate = authorityCertGenerator.genRootCA(//
					certificateId, //
					rootCaValidityPeriod, //
					geographicRegion, //
					subjectAssurance, //
					appPermissions, //
					certIssuePermissions, //
					signingPublicKeyAlgorithm, //
					signingPublicKey, //
					signingPrivateKey, //
					symmetricEncryptionAlgorithm, //
					publicKeyEncryptionAlgorithm, //
					encryptionPublicKey);
		} catch (IllegalArgumentException | SignatureException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private Hostname createHostNameFromString(String rootCaName) {
		Hostname rootCaHostname = null;

		try {
			rootCaHostname = new Hostname(rootCaName);

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return rootCaHostname;
	}

	private void createRootCaKeyPairs() {
		createRootCaSigningKeys();

		createRootCaEncryptionKeys();
	}

	private void createRootCaSigningKeys() {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.rootCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.rootCaSigningKeys.getPrivate(),
				Constants.ROOT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.rootCaSigningKeys.getPublic(),
				Constants.ROOT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
	}

	private void createRootCaEncryptionKeys() {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.rootCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.rootCaEncryptionKeys.getPrivate(),
				Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.rootCaEncryptionKeys.getPublic(),
				Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
	}

	private void readRootCaCertificateAndKeyPairs() {

		readRootCaKeyPairs();

		readRootCaCertificate();
	}

	private void readRootCaCertificate() {
		this.rootCaCertificate = IOUtils.readCertificateFromFile(Constants.ROOT_CA_CERTIFICATE_FILE);

		Logger.shortPrint("[root CA         ] Root CA certificate read from file");
	}

	private void readRootCaKeyPairs() {
		readRootCaSigningKeys();

		readRootCaEncryptionKeys();
	}

	private void readRootCaEncryptionKeys() {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);

		PublicKey publicEncryptionKey = IOUtils
				.readPublicKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		this.rootCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void readRootCaSigningKeys() {
		PrivateKey privateSigningKey = IOUtils.readPrivateKeyFromFile(Constants.ROOT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);

		PublicKey publicSigningKey = IOUtils.readPublicKeyFromFile(Constants.ROOT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.rootCaSigningKeys = new KeyPair(publicSigningKey, privateSigningKey);
	}

	public EtsiTs103097Certificate getCertificate() {
		return this.rootCaCertificate;
	}

	public KeyPair getSigningKeys() {
		return this.rootCaSigningKeys;
	}

	public KeyPair getEncryptionKeys() {
		return this.rootCaEncryptionKeys;
	}

	public HashedId8 getCertificateHashedId8() {
		HashedId8 certificateHashedId8 = null;

		CertChainBuilder certChainBuilder = new CertChainBuilder(PkiUtilsSingleton.getInstance().getCryptoManager());

		try {
			certificateHashedId8 = certChainBuilder.getCertID(this.rootCaCertificate);
		} catch (IllegalArgumentException | NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return certificateHashedId8;
	}

}
