package cits.samuca.pki.certificates;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;

import cits.samuca.utils.PkiUtilsSingleton;
import cits.samuca.utils.Constants;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.Logger;

public class EnrolmentCaCertificate {

	private EtsiTs103097Certificate enrolmentCaCertificate;

	private KeyPair enrolmentCaEncryptionKeys;

	private KeyPair enrolmentCaSigningKeys;

	private EtsiTs103097Certificate[] enrolmentCaChain;

	private EtsiTs103097Certificate rootCaCertificate;

	private KeyPair rootCaSigningKeys;

	public EnrolmentCaCertificate(EtsiTs103097Certificate rootCaCertificate, KeyPair rootCaSigningKeys) {

		this.rootCaCertificate = rootCaCertificate;
		this.rootCaSigningKeys = rootCaSigningKeys;

		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs() {

		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readEnrolmentCaCertificateAndKeyPairs();
		} else {
			createEnrolmentCaCertificateAndKeyPairs();
		}
	}

	private void createEnrolmentCaCertificateAndKeyPairs() {

		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.enrolmentCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		IOUtils.writePrivateKeyToFile(this.enrolmentCaSigningKeys.getPrivate(),
				Constants.ENROLMENT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		IOUtils.writePublicKeyToFile(this.enrolmentCaSigningKeys.getPublic(),
				Constants.ENROLMENT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.enrolmentCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		IOUtils.writePrivateKeyToFile(this.enrolmentCaEncryptionKeys.getPrivate(),
				Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		IOUtils.writePublicKeyToFile(this.enrolmentCaEncryptionKeys.getPublic(),
				Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		String eAName = "EA.samuCA.autostrade.it";

		final long daysOffset = 3;

		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - daysOffset * 24 * 60 * 60 * 1000);
		ValidityPeriod enrolmentCAValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 37);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.enrolmentCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.enrolmentCaEncryptionKeys.getPublic();

		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		createEnrolmentCaCertificate(eAName, //
				enrolmentCAValidityPeriod, //
				subjectAssurance, //
				signingPublicKeyAlgorithm, //
				verificationPublicKey, //
				signerCertificate, //
				signerCertificatePublicKey, //
				signerCertificatePrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey, //
				authorityCertGenerator, //
				geographicRegion//
		);

		this.enrolmentCaChain = new EtsiTs103097Certificate[] { this.enrolmentCaCertificate, this.rootCaCertificate };

		IOUtils.writeCertificateToFile(this.enrolmentCaCertificate, Constants.ENROLMENT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Enrolment CA certificate written to file");
	}

	private void createEnrolmentCaCertificate(String eAName, ValidityPeriod enrolmentCAValidityPeriod,
			SubjectAssurance subjectAssurance, SignatureChoices signingPublicKeyAlgorithm,
			PublicKey verificationPublicKey, EtsiTs103097Certificate signerCertificate,
			PublicKey signerCertificatePublicKey, PrivateKey signerCertificatePrivateKey,
			SymmAlgorithm symmetricEncryptionAlgorithm, BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm,
			PublicKey encryptionPublicKey, ETSIAuthorityCertGenerator authorityCertGenerator,
			GeographicRegion geographicRegion) {

		try {
			this.enrolmentCaCertificate = authorityCertGenerator.genCustomEnrollmentCA(eAName, //
					enrolmentCAValidityPeriod, //
					geographicRegion, //
					subjectAssurance, //
					signingPublicKeyAlgorithm, //
					verificationPublicKey, //
					signerCertificate, //
					signerCertificatePublicKey, //
					signerCertificatePrivateKey, //
					symmetricEncryptionAlgorithm, //
					publicKeyEncryptionAlgorithm, //
					encryptionPublicKey//
			);

		} catch (IllegalArgumentException | SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void readEnrolmentCaCertificateAndKeyPairs() {

		readEnrolmentCaKeyPairs();

		readEnrolmentCaCertificate();
	}

	private void readEnrolmentCaCertificate() {
		this.enrolmentCaCertificate = IOUtils.readCertificateFromFile(Constants.ENROLMENT_CA_CERTIFICATE_FILE);
		this.enrolmentCaChain = new EtsiTs103097Certificate[] { this.enrolmentCaCertificate, this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] Enrolment CA certificate read from file");
	}

	private void readEnrolmentCaKeyPairs() {
		readEnrolmentCaSigningKeys();

		readEnrolmentCaEncryptionKeys();
	}

	private void readEnrolmentCaEncryptionKeys() {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = IOUtils
				.readPublicKeyFromFile(Constants.ENROLMENT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.enrolmentCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void readEnrolmentCaSigningKeys() {
		PrivateKey privateSigningKey = IOUtils
				.readPrivateKeyFromFile(Constants.ENROLMENT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = IOUtils.readPublicKeyFromFile(Constants.ENROLMENT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.enrolmentCaSigningKeys = new KeyPair(publicSigningKey, privateSigningKey);
	}

	public EtsiTs103097Certificate getCertificate() {
		return this.enrolmentCaCertificate;
	}

	public KeyPair getSigningKeys() {
		return this.enrolmentCaSigningKeys;
	}

	public KeyPair getEncryptionKeys() {
		return this.enrolmentCaEncryptionKeys;
	}

	public EtsiTs103097Certificate[] getCaChain() {
		return this.enrolmentCaChain;
	}
}
