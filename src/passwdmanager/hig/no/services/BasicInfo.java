/**
 *
 */
package passwdmanager.hig.no.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Encapsulates basic info, i.e. DG1
 *
 *
 *
 */
public class BasicInfo {

	public String id = null;

	public String web1 = null;

	public String web2 = null;

	public String web3 = null;

	public String web4 = null;

	public BasicInfo(String id, String web1,
			String web2, String web3, String web4) {
		this.id = id;
		this.web1 = web1;
		this.web2 = web2;
		this.web3 = web3;
		this.web4 = web4;
	}

	/**
	 * Constructs a new file based on data in <code>in</code>.
	 *
	 * @param in the input stream to be decoded
	 *
	 * @throws IOException if decoding fails
	 */
	public BasicInfo(InputStream in) throws IOException {
		int len = 0;
		byte[] t = null;
		len = in.read();

		t = new byte[len];
		in.read(t);
		id = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		web1 = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		web2 = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		web3 = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		web4 = new String(t);

	}

	public String toString() {
		return id + "<" + web1 + "<" + web2 + "<" + web3 + "<"
				+ web4;
	}

	/**
	 * Gets the encoded version of this file.
	 */
	public byte[] getEncoded() {
		String[] data = {id, web1, web2, web3, web4};
		int total = 0;
		for (String s : data) {
			total += s.length() + 1;
		}
		byte[] result = new byte[total];
		int offset = 0;
		for (String s : data) {
			result[offset++] = (byte) s.length();
			System.arraycopy(s.getBytes(), 0, result, offset, s.length());
			offset += s.length();
		}

		return result;
	}

	//test
	public static void main(String[] args) throws IOException {
		String a = "123456";
		String b = "google";
		String c = "opensource";
		String d = "github";
		String e = "6park";

		BasicInfo basic = new BasicInfo(a, b, c, d, e);

		byte[] result = basic.getEncoded();

		System.out.println(basic.toString());

		InputStream in = new ByteArrayInputStream(result);

		BasicInfo basic2 = new BasicInfo(in);

		System.out.println(basic2.toString());

	}

}
