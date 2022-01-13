package cits.samuca.utils;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.Url;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

public class GenericCreationUtils {

	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
	
	public static Time32 createNextUpdateThisDateInTheFuture(String aDateInTheFuture) {
		Time32 nextUpdate = null;

		try {
			nextUpdate = new Time32(dateFormat.parse(aDateInTheFuture));
		} catch (ParseException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return nextUpdate;
	}

	public static Url createUrl(String urlString) {
		Url url = null;

		try {
			url = new Url(urlString);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return url;
	}
	
}
