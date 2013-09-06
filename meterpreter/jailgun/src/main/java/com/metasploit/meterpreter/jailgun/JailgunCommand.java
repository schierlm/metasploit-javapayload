package com.metasploit.meterpreter.jailgun;

import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

/**
 * A {@link Command} that returns an {@link Object} or throws a
 * {@link JailgunException}.
 * 
 * @author mihi
 */
public abstract class JailgunCommand implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		try {
			Object value = execute(meterpreter, request);
			response.add(TLVType.TLV_TYPE_JAILGUN_THROWN, Boolean.FALSE);
			fillResponse(response, value);
		} catch (JailgunException ex) {
			response.add(TLVType.TLV_TYPE_JAILGUN_THROWN, Boolean.TRUE);
			fillResponse(response, ex.myCause);
		}
		return ERROR_SUCCESS;
	}

	private void fillResponse(TLVPacket response, Object value) throws IOException {
		if (value == null) {
			response.add(TLVType.TLV_TYPE_JAILGUN_OBJREF, 0);
			response.add(TLVType.TLV_TYPE_JAILGUN_CLASSNAME, "null");
			response.add(TLVType.TLV_TYPE_STRING, "");
		} else {
			response.add(TLVType.TLV_TYPE_JAILGUN_OBJREF, ObjectStore.instance.add(value));
			response.add(TLVType.TLV_TYPE_JAILGUN_CLASSNAME, value.getClass().getName());
			response.add(TLVType.TLV_TYPE_STRING, value.toString());
		}
	}

	protected abstract Object execute(Meterpreter meterpreter, TLVPacket request) throws JailgunException, Exception;

	/**
	 * An exception that should be sent back to the caller (Metasploit) instead
	 * of causing an error.
	 */
	public static class JailgunException extends Exception {

		private Throwable myCause;

		public JailgunException(Throwable cause) {
			super(cause == null ? null : cause.toString());
			this.myCause = cause;
			try {
				Throwable.class.getMethod("initCause", new Class[] {Throwable.class}).invoke(this, new Object[] {cause});
			} catch (Exception ex) {
				// ignore, Java version too old
			}
		}
	}
}
