package cits.samuca.utils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;

public class IOUtils {

	public static void writeCtlToFile(EtsiTs103097DataSigned certificateTrustListMessage, String filename) {

		Logger.shortPrint("[I/O utils       ] writing CTL to " + filename);

		writeEtsiTs103097DataSignedToFile_exitOnProblems(certificateTrustListMessage, filename);
	}

	public static void writeCrlToFile(EtsiTs103097DataSigned certificateRevocationListMessage, String filename) {

		Logger.shortPrint("[I/O utils       ] writing CRL to " + filename);

		writeEtsiTs103097DataSignedToFile_exitOnProblems(certificateRevocationListMessage, filename);
	}
	
	private static void writeEtsiTs103097DataSignedToFile_exitOnProblems(
			EtsiTs103097DataSigned certificateTrustListMessage, String filename) {
		
		try {
			writeEtsiTs103097DataSignedToFile(certificateTrustListMessage, filename);
			
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void writeEtsiTs103097DataSignedToFile(EtsiTs103097DataSigned fileToDump, String filename) throws IOException {

		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));

		fileToDump.encode(dataOutputStream);

		dataOutputStream.close();

	}

	public static void writeCertificateToFile(EtsiTs103097Certificate certificate, String filename) {

		Logger.shortPrint("[I/O utils       ] writing certificate to " + filename);

		DataOutputStream dataOutputStream;
		try {
			dataOutputStream = new DataOutputStream(new FileOutputStream(filename));

			certificate.encode(dataOutputStream);

			dataOutputStream.close();

		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	public static EtsiTs103097Certificate readCertificateFromFile(String filename) {

		EtsiTs103097Certificate certificate = null;

		Logger.shortPrint("[I/O utils       ] reading certificate from " + filename);

		try {
			DataInputStream dataInputStream = new DataInputStream(new FileInputStream(filename));

			certificate = new EtsiTs103097Certificate();

			certificate.decode(dataInputStream);

			dataInputStream.close();

		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return certificate;
	}

	public static void writePrivateKeyToFile(PrivateKey privateKey, String filename) {
		Logger.shortPrint("[                ] writing private key to " + filename);

		exitIfNull(privateKey);

		writeObjectToFile_exitOnProblems(privateKey, filename);
	}

	public static void writePublicKeyToFile(PublicKey publicKey, String filename) {
		Logger.shortPrint("[I/O utils       ] writing public key to " + filename);

		exitIfNull(publicKey);

		writeObjectToFile_exitOnProblems(publicKey, filename);
	}

	private static void writeObjectToFile_exitOnProblems(Object object, String filename) {

		try {
			writeObjectToFile(object, filename);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void exitIfNull(Object object) {
		if (object == null) {
			Logger.shortPrint("[ERROR           ] trying to dump an empty object");
			System.exit(1);
		}
	}

	private static void writeObjectToFile(Object object, String filename) throws FileNotFoundException, IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		
		objectOutputStream.writeObject(object);
		
		objectOutputStream.close();
	}

	public static PrivateKey readPrivateKeyFromFile(String filename) {
		Logger.shortPrint("[I/O utils       ] reading private key from " + filename);

		PrivateKey privateKey = (PrivateKey) readObjectFromFile_exitOnProblems(filename);

		return privateKey;
	}

	public static PublicKey readPublicKeyFromFile(String filename) {
		Logger.shortPrint("[I/O utils       ] reading public key from " + filename);

		PublicKey publicKey = (PublicKey) readObjectFromFile_exitOnProblems(filename);

		return publicKey;
	}

	private static Object readObjectFromFile_exitOnProblems(String filename) {

		Object object = null;

		try {
			object = readObjectFromFile(filename);
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return object;
	}

	private static Object readObjectFromFile(String filename) throws IOException, ClassNotFoundException {
		Object object;
		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		object = objectInputStream.readObject();
		objectInputStream.close();
		return object;
	}
}
