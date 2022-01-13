package cits.samuca.pki.certificates;

import java.io.FileNotFoundException;
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

	public TrustListManagerCertificate()
			throws InvalidKeyException, SignatureException, ClassNotFoundException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException {
		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs()
			throws SignatureException, IOException, InvalidKeyException, ClassNotFoundException,
			IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {
		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readCertificateAndKeyPairs();
		} else {
			createCertificateAndKeyPairs();
		}
	}

	private void readCertificateAndKeyPairs() throws IllegalArgumentException, SignatureException, IOException,
			InvalidKeyException, ClassNotFoundException {

		readCertificate();

		readKeyPairs();
	}

	private void readCertificate() throws FileNotFoundException, IOException {
		this.certificate = IOUtils.readCertificateFromFile(Constants.TLM_CERTIFICATE_FILE);

		Logger.shortPrint("[root CA         ] Root CA certificate read from file");
	}

	private void readKeyPairs() throws IOException, ClassNotFoundException {
		readSigningKeys();

		readEncryptionKeys();
	}

	private void readSigningKeys() throws IOException, ClassNotFoundException {
		PrivateKey privateSigningKey = IOUtils.readPrivateKeyFromFile(Constants.TLM_SIGNING_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicSigningKey = IOUtils.readPublicKeyFromFile(Constants.TLM_SIGNING_KEYS_PUBLIC_KEY_FILE);
		this.signingKeys = new KeyPair(publicSigningKey, privateSigningKey);
	}

	private void readEncryptionKeys() throws IOException, ClassNotFoundException {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.TLM_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = IOUtils.readPublicKeyFromFile(Constants.TLM_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.encryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void createCertificateAndKeyPairs() throws IllegalArgumentException, SignatureException, IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {

		createKeyPairs();

		createCertificate();
	}

	private void createKeyPairs() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		createSigningKeys();

		createEncryptionKeys();
	}

	private void createSigningKeys() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.signingKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.signingKeys.getPrivate(), Constants.TLM_SIGNING_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.signingKeys.getPublic(), Constants.TLM_SIGNING_KEYS_PUBLIC_KEY_FILE);
	}

	private void createEncryptionKeys() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.encryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.encryptionKeys.getPrivate(), Constants.TLM_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.encryptionKeys.getPublic(), Constants.TLM_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
	}

	private void createCertificate() throws SignatureException, IOException, FileNotFoundException,
			IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {

		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		ValidityPeriod tlmValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);

		final String tlmName = "tlm.autostrade.it";

		final int assuranceLevel = 3;
		final int confidenceLevel = 2;
		final SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);

		final CertificateId certificateId = new CertificateId(new Hostname(tlmName));

		final PsidSsp[] appPermissions = new PsidSsp[] {
//						new PsidSsp(new Psid(622),
//								new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("01"))),
				new PsidSsp(new Psid(624), new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.bitmapSsp,
						Hex.decode("0138"))) };

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

		IOUtils.writeCertificateToFile(this.certificate, Constants.TLM_CERTIFICATE_FILE);
		IOUtils.writeCertificateToFile(this.certificate, Constants.TLM_CERTIFICATE_FILE_FOR_COHDA);
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
