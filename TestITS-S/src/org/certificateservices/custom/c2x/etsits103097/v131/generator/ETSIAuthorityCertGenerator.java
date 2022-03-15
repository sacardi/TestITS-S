/************************************************************************
*                                                                       *
*  Certificate Service -  Car2Car Core                                  *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.custom.c2x.etsits103097.v131.generator;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseAuthorityCertGenerator;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.*;

/**
 * Certificate Generator class for generating CA certificates for ETSI TS 103 097 v 1.3.1 standard.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ETSIAuthorityCertGenerator extends BaseAuthorityCertGenerator {

	public static final byte ETSI_102_941_v121_SSP_VERSION = 1;

	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public ETSIAuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager) throws SignatureException{
		super(cryptoManager, false);
	}
	
	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public ETSIAuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException {
		super(cryptoManager, useUncompressed);
	}

	/**
	 * Method to generate a simple self signed root CA.
	 * 
	 * @param caName the id if the certificate, a string representation, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param minChainDepth the minimal chain length of this PKI hierarchy, Required
	 * @param chainDepthRange the chain depth range, see 6.4.30 PsidGroupPermissions for details, Required
	 * @param cTLServiceSpecificPermissions the SSP data used for CTL Service Specific Permissions as defined as 2 octets
	 *                                      in 102 941 v1.3.1.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new self signed certificate with root CA profile.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genRootCA(
			String caName,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			int minChainDepth,
			int chainDepthRange,
			byte[] cTLServiceSpecificPermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PrivateKey signPrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{
		CertificateId id = new CertificateId(new Hostname(caName));
		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(true, true));
		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {pgp};

		ServiceSpecificPermissions crlSSP = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,new byte[] {ETSI_102_941_v121_SSP_VERSION});
		PsidSsp crlPermissions = new PsidSsp(CRLService,crlSSP);

		ServiceSpecificPermissions ctlSSP = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,cTLServiceSpecificPermissions);
		PsidSsp ctlPermissions = new PsidSsp(CTLService,ctlSSP);

		PsidSsp[] appPermissions = new PsidSsp[]{crlPermissions,ctlPermissions};
		return genRootCA(id,validityPeriod,region,null,appPermissions,certIssuePermissions,signingPublicKeyAlgorithm,
				signPublicKey,signPrivateKey,symmAlgorithm,encPublicKeyAlgorithm,encPublicKey);

	}

	/**
	 * A more general Root CA generator constructor for custom Root CA certificate profile.
	 *
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Required
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions list of appPermissions, use null to not set any app permissions.
	 * @param certIssuePermissions list of certIssuePermissions, use null to not set any cert issue permissions.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
	 * @param symmAlgorithm the type of symmetric algorithm used when signing.
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new self signed certificate with root CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genRootCA(
			CertificateId id,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			PsidGroupPermissions[] certIssuePermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			PrivateKey signPrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{


		return (EtsiTs103097Certificate) super.genRootCA(id,validityPeriod,region,subjectAssurance,appPermissions,
				certIssuePermissions, signingPublicKeyAlgorithm, signPublicKey, signPrivateKey,symmAlgorithm,
				encPublicKeyAlgorithm, encPublicKey);

	}

	/**
	 * Method to generate a simple self signed Trust List Manager certificate.
	 *
	 * @param name the id if the certificate, a string representation, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param cTLServiceSpecificPermissions the SSP data used for CTL Service Specific Permissions as defined as 2 octets
	 *                                      in 102 941 v1.3.1.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
	 * @return a new self signed certificate with Trust List Manager profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genTrustListManagerCert(
			String name,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			byte[] cTLServiceSpecificPermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			PrivateKey signPrivateKey) throws IllegalArgumentException,  SignatureException, IOException{
		CertificateId id = new CertificateId(new Hostname(name));
		ServiceSpecificPermissions ctlSSP = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,cTLServiceSpecificPermissions);
		PsidSsp ctlPermissions = new PsidSsp(CTLService,ctlSSP);

		PsidSsp[] appPermissions = new PsidSsp[]{ctlPermissions};
		return genTrustListManagerCert(id,validityPeriod,region,null,appPermissions,signingPublicKeyAlgorithm,
				signPublicKey,signPrivateKey);

	}

	/**
	 * A more general Trust List Manager generator constructor for custom Root CA certificate profile.
	 *
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Required
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions list of appPermissions, use null to not set any app permissions.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
	 * @return a new self signed certificate with root CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genTrustListManagerCert(
			CertificateId id,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			PrivateKey signPrivateKey) throws IllegalArgumentException,  SignatureException, IOException{


		return (EtsiTs103097Certificate) super.genRootCA(id,validityPeriod,region,subjectAssurance,appPermissions,
				null, signingPublicKeyAlgorithm, signPublicKey, signPrivateKey,null,
				null, null);

	}

	/**
	 * Method to generate a simple enrollment CA with all cert permissions for enrollment CAs.
	 *
	 * @param caName the id if the certificate, a string representation, Required.
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required if type is explicit
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new signed certificate with enrollment CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genEnrollmentCA(
			String caName,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		CertificateId id = new CertificateId(new Hostname(caName));

		// TODO More specific security management permissions.
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 1, 0, new EndEntityType(false, true));
		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {pgp};

		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("010E")));
		PsidSsp[] appPermissions = new PsidSsp[] {appPermCertMan};

		return genSubCA(id, validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signCertificatePublicKey,signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
	}
	

	/**
	 * Method to generate a simple enrollment CA with all cert permissions for enrollment CAs.
	 *
	 * @param caName the id if the certificate, a string representation, Required.
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required if type is explicit
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new signed certificate with enrollment CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genCustomEnrollmentCA(
			String caName,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		CertificateId id = new CertificateId(new Hostname(caName));

		// TODO More specific security management permissions.
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 1, 0, new EndEntityType(false, true));

		int minChainDepth1 = 1;
		int chainDepthRange1 = 0;
		int minChainDepth2 = 1;
		int chainDepthRange2 = 0;

		final boolean appBoolean1 = false;
		final boolean enrollBoolean1 = true;
		final boolean appBoolean2 = true;
		final boolean enrollBoolean2 = false;
		
//		final PsidGroupPermissions firstPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { new PsidSspRange(new Psid(36),
//								new SspRange(SspRangeChoices.bitmapSspRange,
//										new BitmapSspRange(Hex.decode("01FFFC"), Hex.decode("FF0003")))) })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));
		

		PsidSspRange psidSspRange36 = new PsidSspRange(new Psid(36), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFC"), Hex.decode("FF0003"))));
		PsidSspRange psidSspRange37 = new PsidSspRange(new Psid(37), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFF"), Hex.decode("FF000000"))));
//		final PsidGroupPermissions secondPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { secondPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange psidSspRange137 = new PsidSspRange(new Psid(137), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01E0"), Hex.decode("FF1F"))));

		PsidSspRange psidSspRange138 = new PsidSspRange(new Psid(138), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));

		PsidSspRange psidSspRange139 = new PsidSspRange(new Psid(139), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFFFFF8"), Hex.decode("FF0000000007"))));

		PsidSspRange psidSspRange140 = new PsidSspRange(new Psid(140), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFE0"), Hex.decode("FF00001F"))));

//		final PsidGroupPermissions thirdPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { thirdPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange psidSspRange141 = new PsidSspRange(new Psid(141), null);
//		final PsidGroupPermissions fourthPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { fourthPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange psidSspRange623 = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));
//		final PsidGroupPermissions fifthPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { fifthPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		final PsidGroupPermissions firstPsidGroupPermissions = new PsidGroupPermissions(
				new SubjectPermissions(SubjectPermissionsChoices.explicit, //
						new SequenceOfPsidSspRange(new PsidSspRange[] { //
								psidSspRange36, //
								psidSspRange37, //
								psidSspRange137, //
								psidSspRange138, //
								psidSspRange139, //
								psidSspRange140, //
								psidSspRange141, //
								psidSspRange623 //
						})), //
				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange sixthPsidSspRange = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));

		final PsidGroupPermissions sixthPsidGroupPermissions = new PsidGroupPermissions(
				new SubjectPermissions(SubjectPermissionsChoices.explicit, //
						new SequenceOfPsidSspRange(new PsidSspRange[] { //
								sixthPsidSspRange //
						})), //
				minChainDepth2, chainDepthRange2, new EndEntityType(appBoolean2, enrollBoolean2));

		final PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] { //
				firstPsidGroupPermissions, //
//				secondPsidGroupPermissions, //
//				thirdPsidGroupPermissions, //
//				fourthPsidGroupPermissions, //
//				fifthPsidGroupPermissions, //
				sixthPsidGroupPermissions //
		};

//		final PsidGroupPermissions secondPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { new PsidSspRange(new Psid(37),
//								new SspRange(SspRangeChoices.bitmapSspRange,
//										new BitmapSspRange(Hex.decode("01FFFFFF"), Hex.decode("FF000000")))) })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));
//		
//		final PsidGroupPermissions sixthPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { new PsidSspRange(new Psid(623),
//								new SspRange(SspRangeChoices.bitmapSspRange,
//										new BitmapSspRange(Hex.decode("013E"), Hex.decode("FFC1")))) })),
//				minChainDepth2, chainDepthRange2, new EndEntityType(appBoolean2, enrollBoolean2));

//		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {pgp};
//		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {firstPsidGroupPermissions};
		
//		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("010E")));
		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("010E") ));
		PsidSsp[] appPermissions = new PsidSsp[] {appPermCertMan};
//		appPermissions = null;

		return genSubCA(id, validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signCertificatePublicKey,signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
	}

	/**
	 * Method to generate a simple autorization CA with all cert permissions for enrollment CAs.
	 *
	 * @param caName the id if the certificate, a string representation, Required.
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required if type is explicit
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new signed certificate with enrollment CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genAuthorizationCA(
			String caName,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		CertificateId id = new CertificateId(new Hostname(caName));
        // TODO More specific security management permissions.
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {pgp};

		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
		PsidSsp[] appPermissions = new PsidSsp[] {appPermCertMan};

		return genSubCA(id, validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signCertificatePublicKey,signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
	}
	
	public EtsiTs103097Certificate genCustomAuthorizationCA(
			String caName,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		CertificateId id = new CertificateId(new Hostname(caName));
        // TODO More specific security management permissions.
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
		

		int minChainDepth1 = 1;
		int chainDepthRange1 = 0;

		final boolean appBoolean1 = true;
		final boolean enrollBoolean1 = false;
		
//		final PsidGroupPermissions firstPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { new PsidSspRange(new Psid(36),
//								new SspRange(SspRangeChoices.bitmapSspRange,
//										new BitmapSspRange(Hex.decode("01FFFC"), Hex.decode("FF0003")))) })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));
		

		PsidSspRange psidSspRange36 = new PsidSspRange(new Psid(36), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFC"), Hex.decode("FF0003"))));
		PsidSspRange psidSspRange37 = new PsidSspRange(new Psid(37), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFF"), Hex.decode("FF000000"))));
//		final PsidGroupPermissions secondPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { secondPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange psidSspRange137 = new PsidSspRange(new Psid(137), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01E0"), Hex.decode("FF1F"))));

		PsidSspRange psidSspRange138 = new PsidSspRange(new Psid(138), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));

		PsidSspRange psidSspRange139 = new PsidSspRange(new Psid(139), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFFFFFF8"), Hex.decode("FF0000000007"))));

		PsidSspRange psidSspRange140 = new PsidSspRange(new Psid(140), new SspRange(SspRangeChoices.bitmapSspRange,
				new BitmapSspRange(Hex.decode("01FFFFE0"), Hex.decode("FF00001F"))));

//		final PsidGroupPermissions thirdPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { thirdPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		PsidSspRange psidSspRange141 = new PsidSspRange(new Psid(141), null);
//		final PsidGroupPermissions fourthPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { fourthPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

//		PsidSspRange psidSspRange623 = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
//				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));
//		final PsidGroupPermissions fifthPsidGroupPermissions = new PsidGroupPermissions(
//				new SubjectPermissions(SubjectPermissionsChoices.explicit,
//						new SequenceOfPsidSspRange(new PsidSspRange[] { fifthPsidSspRange })),
//				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

		final PsidGroupPermissions firstPsidGroupPermissions = new PsidGroupPermissions(
				new SubjectPermissions(SubjectPermissionsChoices.explicit, //
						new SequenceOfPsidSspRange(new PsidSspRange[] { //
								psidSspRange36, //
								psidSspRange37, //
								psidSspRange137, //
								psidSspRange138, //
								psidSspRange139, //
								psidSspRange140, //
								psidSspRange141, //
//								psidSspRange623 //
						})), //
				minChainDepth1, chainDepthRange1, new EndEntityType(appBoolean1, enrollBoolean1));

//		PsidSspRange sixthPsidSspRange = new PsidSspRange(new Psid(623), new SspRange(SspRangeChoices.bitmapSspRange,
//				new BitmapSspRange(Hex.decode("01C0"), Hex.decode("FF3F"))));


		final PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] { //
				firstPsidGroupPermissions, //
//				secondPsidGroupPermissions, //
//				thirdPsidGroupPermissions, //
//				fourthPsidGroupPermissions, //
//				fifthPsidGroupPermissions, //
//				sixthPsidGroupPermissions //
		};
		
//		PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[] {pgp};

		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp, Hex.decode("0132")));
		PsidSsp[] appPermissions = new PsidSsp[] {appPermCertMan};

		return genSubCA(id, validityPeriod, region, subjectAssurance, appPermissions, certIssuePermissions, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signCertificatePublicKey,signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
	}

	/**
	 * Method to create a general sub CA either enrollment or authorization CA with custom specified
	 * appPermissions and certIssuePermissions.
	 *
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions list of appPermissions, use null to not set any app permissions.
	 * @param certIssuePermissions list of certIssuePermissions, use null to not set any cert issue permissions.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a newly created sub ca certificate.
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genSubCA(
			CertificateId id,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			PsidGroupPermissions[] certIssuePermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		SequenceOfPsidSsp appPermissionsSequence = null;
		if(appPermissions != null){
			appPermissionsSequence = new SequenceOfPsidSsp(appPermissions);
		}
		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SequenceOfPsidGroupPermissions certIssuePermissionsSequence = null;
		if(certIssuePermissions != null){
			certIssuePermissionsSequence = new SequenceOfPsidGroupPermissions(certIssuePermissions);
		}

		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}

		PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
		VerificationKeyIndicator vki = new VerificationKeyIndicator(verifyKeyIndicator);
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0), validityPeriod, region, subjectAssurance, appPermissionsSequence, certIssuePermissionsSequence, null, false, encryptionKey, vki);
		return (EtsiTs103097Certificate) genCert(tbs, CertificateType.explicit, signingPublicKeyAlgorithm, signPublicKey, signCertificatePrivateKey, signCertificatePublicKey,signerCertificate);

	}

	@Override
	protected Certificate newCertificate(IssuerIdentifier issuerIdentifier, ToBeSignedCertificate tbs,Signature signature){
		return new EtsiTs103097Certificate(issuerIdentifier,tbs,signature);
	}

	

}