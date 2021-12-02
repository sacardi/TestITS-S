package cits.pki;

public class Logger {
	public enum VerbosityLevel {
		SHORT_MESSAGES, DEBUG, DEBUG_AND_SHORT_MESSAGES
	}

	private static VerbosityLevel verbosity;

	public static void setVerbosity(VerbosityLevel verbosityLevel) {
		verbosity = verbosityLevel;
	}

	public static void shortPrint(String stringToPrint) {
		if (verbosity == VerbosityLevel.SHORT_MESSAGES || verbosity == VerbosityLevel.DEBUG_AND_SHORT_MESSAGES) {
			print(stringToPrint);
		}
	}

	public static void debugPrint(String stringToPrint) {
		if (verbosity == VerbosityLevel.DEBUG || verbosity == VerbosityLevel.DEBUG_AND_SHORT_MESSAGES) {
			print(stringToPrint);
		}
	}

	private static void print(String stringToPrint) {
		System.out.println(stringToPrint);
	}
}
