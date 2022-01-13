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

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;

import cits.samuca.utils.Constants;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

public class AuthorizationCaCertificate {

	private KeyPair authorizationCaEncryptionKeys;

	private KeyPair authorizationCaSigningKeys;

	private EtsiTs103097Certificate authorizationCaCertificate;

	private EtsiTs103097Certificate[] authorizationCAChain;

	private EtsiTs103097Certificate rootCaCertificate;
	private KeyPair rootCaSigningKeys;

	public AuthorizationCaCertificate(EtsiTs103097Certificate rootCaCertificate, KeyPair rootCaSigningKeys) {

		this.rootCaCertificate = rootCaCertificate;
		this.rootCaSigningKeys = rootCaSigningKeys;

		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs() {
		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readAuthorizationCaCertificateAndKeyPairs();
		} else {
			createAuthorizationCaCertificateAndKeyPairs();
		}
	}

	private void createAuthorizationCaCertificateAndKeyPairs() {

		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.authorizationCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		IOUtils.writePrivateKeyToFile(this.authorizationCaSigningKeys.getPrivate(),
				Constants.AUTHORIZATION_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		IOUtils.writePublicKeyToFile(this.authorizationCaSigningKeys.getPublic(),
				Constants.AUTHORIZATION_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);

		this.authorizationCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		IOUtils.writePrivateKeyToFile(this.authorizationCaEncryptionKeys.getPrivate(),
				Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		IOUtils.writePublicKeyToFile(this.authorizationCaEncryptionKeys.getPublic(),
				Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);

		String aAName = "AA.samuCA.autostrade.it";
		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000);
		ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 15);
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);
		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey verificationPublicKey = this.authorizationCaSigningKeys.getPublic();
		EtsiTs103097Certificate signerCertificate = this.rootCaCertificate;
		PublicKey signerCertificatePublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signerCertificatePrivateKey = this.rootCaSigningKeys.getPrivate();
		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;
		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.authorizationCaEncryptionKeys.getPublic();

		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		createAuthorizationCaCertificate(aAName, //
				authorityCAValidityPeriod, //
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
				geographicRegion);

		this.authorizationCAChain = new EtsiTs103097Certificate[] { this.authorizationCaCertificate,
				this.rootCaCertificate };

		IOUtils.writeCertificateToFile(this.authorizationCaCertificate, Constants.AUTHORIZATION_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Authorization CA certificate written to file");
	}

	private void createAuthorizationCaCertificate(String aAName, ValidityPeriod authorityCAValidityPeriod,
			SubjectAssurance subjectAssurance, SignatureChoices signingPublicKeyAlgorithm,
			PublicKey verificationPublicKey, EtsiTs103097Certificate signerCertificate,
			PublicKey signerCertificatePublicKey, PrivateKey signerCertificatePrivateKey,
			SymmAlgorithm symmetricEncryptionAlgorithm, BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm,
			PublicKey encryptionPublicKey, ETSIAuthorityCertGenerator authorityCertGenerator,
			GeographicRegion geographicRegion) {
		try {
			this.authorizationCaCertificate = authorityCertGenerator.genAuthorizationCA(aAName, //
					authorityCAValidityPeriod, //
					geographicRegion, //
					subjectAssurance, //
					signingPublicKeyAlgorithm, //
					verificationPublicKey, //
					signerCertificate, //
					signerCertificatePublicKey, //
					signerCertificatePrivateKey, //
					symmetricEncryptionAlgorithm, //
					publicKeyEncryptionAlgorithm, //
					encryptionPublicKey //
			);
		} catch (IllegalArgumentException | SignatureException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void readAuthorizationCaCertificateAndKeyPairs() {

		readAuthorizationCaKeyPairs();

		readAuthorizationCaCertificate();
	}

	private void readAuthorizationCaKeyPairs() {

		readAuthorizationCaSigningKeys();

		readAuthorizationCaEncryptionKeys();
	}

	private void readAuthorizationCaEncryptionKeys() {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = IOUtils
				.readPublicKeyFromFile(Constants.AUTHORIZATION_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.authorizationCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void readAuthorizationCaSigningKeys() {
		PrivateKey privateSigningKey = IOUtils
				.readPrivateKeyFromFile(Constants.AUTHORIZATION_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = IOUtils
				.readPublicKeyFromFile(Constants.AUTHORIZATION_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.authorizationCaSigningKeys = new KeyPair(publicSigningKey, privateSigningKey);
	}

	private void readAuthorizationCaCertificate() {
		this.authorizationCaCertificate = IOUtils.readCertificateFromFile(Constants.AUTHORIZATION_CA_CERTIFICATE_FILE);
		this.authorizationCAChain = new EtsiTs103097Certificate[] { this.authorizationCaCertificate,
				this.rootCaCertificate };

		Logger.shortPrint("[root CA         ] Authorization CA certificate read from file");
	}

	public EtsiTs103097Certificate getCertificate() {
		return this.authorizationCaCertificate;
	}

	public KeyPair getSigningKeys() {
		return this.authorizationCaSigningKeys;
	}

	public KeyPair getEncryptionKeys() {
		return this.authorizationCaEncryptionKeys;
	}

	public EtsiTs103097Certificate[] getCaChain() {
		return this.authorizationCAChain;
	}
}
