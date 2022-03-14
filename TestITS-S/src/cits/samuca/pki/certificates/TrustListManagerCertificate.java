package cits.samuca.pki.certificates;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;

import cits.samuca.utils.Constants;
import cits.samuca.utils.IOUtils;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;

public class TrustListManagerCertificate {

	private EtsiTs103097Certificate certificate;

	private KeyPair signingKeys;

	private KeyPair encryptionKeys;

	public TrustListManagerCertificate() {
		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs() {
		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readCertificateAndKeyPairs();
		} else {
			createCertificateAndKeyPairs();
		}
	}

	private void readCertificateAndKeyPairs() {

		readCertificate();

		readKeyPairs();
	}

	private void readCertificate() {
		this.certificate = IOUtils.readCertificateFromFile(Constants.TLM_CERTIFICATE_FILE);

		Logger.shortPrint("[root CA         ] Root CA certificate read from file");
	}

	private void readKeyPairs() {
		readSigningKeys();

		readEncryptionKeys();
	}

	private void readSigningKeys() {
		PrivateKey privateSigningKey = IOUtils.readPrivateKeyFromFile(Constants.TLM_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = IOUtils.readPublicKeyFromFile(Constants.TLM_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.signingKeys = new KeyPair(publicSigningKey, privateSigningKey);
	}

	private void readEncryptionKeys() {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.TLM_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = IOUtils.readPublicKeyFromFile(Constants.TLM_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.encryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void createCertificateAndKeyPairs() {

		createKeyPairs();

		createCertificate();
	}

	private void createKeyPairs() {
		createSigningKeys();

		createEncryptionKeys();
	}

	private void createSigningKeys() {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.signingKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.signingKeys.getPrivate(), Constants.TLM_SIGNING_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.signingKeys.getPublic(), Constants.TLM_SIGNING_KEYS_PUBLIC_KEY_FILE);
	}

	private void createEncryptionKeys() {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.encryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.encryptionKeys.getPrivate(), Constants.TLM_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.encryptionKeys.getPublic(), Constants.TLM_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
	}

	private void createCertificate() {
		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		final long daysOffset = 3;

		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - daysOffset * 24 * 60 * 60 * 1000);

		ValidityPeriod tlmValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 45);

		final String tlmName = "tlm.autostrade.it";

		final int assuranceLevel = 3;
		final int confidenceLevel = 2;
		final SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);

		final Hostname hostNameFromString = createHostNameFromString(tlmName);
		final CertificateId certificateId = new CertificateId(hostNameFromString);

		final PsidSsp[] appPermissions = createAppPermissions();

		createTrustListManagerCertificate(authorityCertGenerator, geographicRegion, tlmValidityPeriod, subjectAssurance,
				certificateId, appPermissions);

		IOUtils.writeCertificateToFile(this.certificate, Constants.TLM_CERTIFICATE_FILE);
		IOUtils.writeCertificateToFile(this.certificate, Constants.TLM_CERTIFICATE_FILE_FOR_COHDA);
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

	private PsidSsp[] createAppPermissions() {
		PsidSsp[] appPermissions = null;

		try {
			appPermissions = new PsidSsp[] {
//						new PsidSsp(new Psid(622),
//								new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("01"))),
					new PsidSsp(new Psid(624), new ServiceSpecificPermissions(
							ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("0138"))) };

		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return appPermissions;
	}

	private void createTrustListManagerCertificate(ETSIAuthorityCertGenerator authorityCertGenerator,
			GeographicRegion geographicRegion, ValidityPeriod tlmValidityPeriod,
			final SubjectAssurance subjectAssurance, final CertificateId certificateId,
			final PsidSsp[] appPermissions) {

		try {
			this.certificate = authorityCertGenerator.genTrustListManagerCert(//
					certificateId, //
					tlmValidityPeriod, //
					geographicRegion, //
					subjectAssurance, //
					appPermissions, //
					SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
					this.signingKeys.getPublic(), // signPublicKey
					this.encryptionKeys.getPrivate() // signPrivateKey
			);

		} catch (IllegalArgumentException | SignatureException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	public EtsiTs103097Certificate getCertificate() {
		return this.certificate;
	}

	public KeyPair getSigningKeys() {
		return this.signingKeys;
	}

	public KeyPair getEncryptionKeys() {
		return this.encryptionKeys;
	}
}
