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

	public static void writeCtlToFile(EtsiTs103097DataSigned certificateTrustListMessage, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		certificateTrustListMessage.encode(dataOutputStream);
		dataOutputStream.close();
	}

	public static void writeCertificateToFile(EtsiTs103097Certificate certificate, String filename)
			throws FileNotFoundException, IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(new FileOutputStream(filename));
		certificate.encode(dataOutputStream);
		dataOutputStream.close();
	}
	
	public static EtsiTs103097Certificate readCertificateFromFile(String filename)
			throws FileNotFoundException, IOException {
		DataInputStream dataInputStream = new DataInputStream(new FileInputStream(filename));
		
		EtsiTs103097Certificate certificate = new EtsiTs103097Certificate();
		certificate.decode(dataInputStream);;
		dataInputStream.close();

		return certificate;
	}

	public static void writePrivateKeyToFile(PrivateKey privateKey, String filename) throws IOException {
		if (privateKey == null) {
			System.out.println("ERROR: key for " + filename + "is null.");
			System.exit(1);
		}
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(privateKey);
		objectOutputStream.close();
	}
	
	public static void writePublicKeyToFile(PublicKey publicKey, String filename) throws IOException {
		if (publicKey == null) {
			System.out.println("ERROR: key for " + filename + "is null.");
			System.exit(1);
		}
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(publicKey);
		objectOutputStream.close();
	}

	public static PrivateKey readPrivateKeyFromFile(String filename) throws IOException, ClassNotFoundException {
		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		PrivateKey privateKey = (PrivateKey) objectInputStream.readObject();
		objectInputStream.close();

		return privateKey;
	}
	
	public static PublicKey readPublicKeyFromFile(String filename) throws IOException, ClassNotFoundException {
		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		PublicKey publicKey = (PublicKey) objectInputStream.readObject();
		objectInputStream.close();

		return publicKey;
	}
}
