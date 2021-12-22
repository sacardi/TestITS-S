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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;

import cits.samuca.utils.Constants;
import cits.samuca.utils.Logger;
import cits.samuca.utils.PkiUtilsSingleton;
import cits.samuca.utils.IOUtils;

public class RootCaCertificate {

	private EtsiTs103097Certificate rootCaCertificate;

	private KeyPair rootCaSigningKeys;

	private KeyPair rootCaEncryptionKeys;

	public RootCaCertificate() throws SignatureException, FileNotFoundException, IOException, InvalidKeyException,
			IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException,
			ClassNotFoundException {

		readOrCreateCertificateAndKeyPairs();
	}

	private void readOrCreateCertificateAndKeyPairs()
			throws SignatureException, IOException, InvalidKeyException, ClassNotFoundException,
			IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {
		if (Constants.READ_CERTIFICATES_FROM_FILE_INSTEAD_OF_CREATING_THEM) {
			readRootCaCertificateAndKeyPairs();
		} else {
			createRootCaCertificateAndKeyPairs();
		}
	}

	private void createRootCaCertificateAndKeyPairs()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {

		createRootCaKeyPairs();

		createRootCaCertificate();
	}

	private void createRootCaCertificate() throws SignatureException, IOException, FileNotFoundException,
			IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, BadCredentialsException {
		String rootCaName = "samuCA.autostrade.it";

		final Date threeDaysBeforeNow = new Date(System.currentTimeMillis() - 3 * 24 * 60 * 60 * 1000);
		ValidityPeriod rootCaValidityPeriod = new ValidityPeriod(threeDaysBeforeNow, DurationChoices.years, 45);

		int minChainDepth = 3;
		int chainDepthRange = -1;

		byte[] serviceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries = Hex.decode("0138");

		SignatureChoices signingPublicKeyAlgorithm = SignatureChoices.ecdsaNistP256Signature;
		PublicKey signingPublicKey = this.rootCaSigningKeys.getPublic();
		PrivateKey signingPrivateKey = this.rootCaSigningKeys.getPrivate();

		SymmAlgorithm symmetricEncryptionAlgorithm = SymmAlgorithm.aes128Ccm;

		BasePublicEncryptionKeyChoices publicKeyEncryptionAlgorithm = BasePublicEncryptionKeyChoices.ecdsaNistP256;
		PublicKey encryptionPublicKey = this.rootCaEncryptionKeys.getPublic();

		ETSIAuthorityCertGenerator authorityCertGenerator = PkiUtilsSingleton.getInstance().getAuthorityCertGenerator();

		GeographicRegion geographicRegion = PkiUtilsSingleton.getInstance().getGeographicRegion();

		this.rootCaCertificate = authorityCertGenerator.genRootCA(//
				rootCaName, //
				rootCaValidityPeriod, //
				geographicRegion, //
				minChainDepth, //
				chainDepthRange, //
				serviceSpecificPermissions_canSignCtlWith_EA_AA_DC_entries, //
				signingPublicKeyAlgorithm, //
				signingPublicKey, //
				signingPrivateKey, //
				symmetricEncryptionAlgorithm, //
				publicKeyEncryptionAlgorithm, //
				encryptionPublicKey);

		IOUtils.writeCertificateToFile(this.rootCaCertificate, Constants.ROOT_CA_CERTIFICATE_FILE);
		Logger.shortPrint("[root CA         ] Root CA certificate written to file");
	}

	private void createRootCaKeyPairs() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		createRootCaSigningKeys();

		createRootCaEncryptionKeys();
	}

	private void createRootCaSigningKeys() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.rootCaSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.rootCaSigningKeys.getPrivate(),
				Constants.ROOT_CA_SIGNING_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.rootCaSigningKeys.getPublic(),
				Constants.ROOT_CA_SIGNING_KEYS_PUBLIC_KEY_FILE);
	}

	private void createRootCaEncryptionKeys() throws IOException, InvalidKeyException, IllegalArgumentException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, BadCredentialsException {
		DefaultCryptoManager cryptoManager = PkiUtilsSingleton.getInstance().getCryptoManager();

		this.rootCaEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		IOUtils.writePrivateKeyToFile(this.rootCaEncryptionKeys.getPrivate(),
				Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);

		IOUtils.writePublicKeyToFile(this.rootCaEncryptionKeys.getPublic(),
				Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
	}

	private void readRootCaCertificateAndKeyPairs() throws IllegalArgumentException, SignatureException, IOException,
			InvalidKeyException, ClassNotFoundException {

		readRootCaKeyPairs();

		readRootCaCertificate();
	}

	private void readRootCaCertificate() throws FileNotFoundException, IOException {
		this.rootCaCertificate = IOUtils.readCertificateFromFile(Constants.ROOT_CA_CERTIFICATE_FILE);

		Logger.shortPrint("[root CA         ] Root CA certificate read from file");
	}

	private void readRootCaKeyPairs() throws IOException, ClassNotFoundException {
		readRootCaSigningKeys();

		readRootCaEncryptionKeys();
	}

	private void readRootCaEncryptionKeys() throws IOException, ClassNotFoundException {
		PrivateKey privateEncryptionKey = IOUtils
				.readPrivateKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PRIVATE_KEY_FILE);
		PublicKey publicEncryptionKey = IOUtils
				.readPublicKeyFromFile(Constants.ROOT_CA_ENCRYPTION_KEYS_PUBLIC_KEY_FILE);
		this.rootCaEncryptionKeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
	}

	private void readRootCaSigningKeys() throws IOException, ClassNotFoundException {
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

}
