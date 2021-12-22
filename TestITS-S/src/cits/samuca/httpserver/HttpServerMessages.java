package cits.samuca.httpserver;

import akka.http.javadsl.ServerBinding;

public class HttpServerMessages {
	public interface Message {
	}

	public static final class StartFailed implements Message {
		final Throwable ex;

		public StartFailed(Throwable ex) {
			this.ex = ex;
		}
	}

	public static final class StartSucceeded implements Message {
		final ServerBinding binding;

		public StartSucceeded(ServerBinding binding) {
			this.binding = binding;
		}
	}

	public static final class Stop implements Message {
	}
}
