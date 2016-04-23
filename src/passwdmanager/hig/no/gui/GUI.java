package passwdmanager.hig.no.gui;

import java.io.InputStream;
import java.security.Security;
import java.util.Locale;

import javax.smartcardio.CardTerminal;

import passwdmanager.hig.no.events.CardActionEvents;
import passwdmanager.hig.no.lds.DG_COM;
import passwdmanager.hig.no.services.BasicService;
import passwdmanager.hig.no.services.CardListener;
import passwdmanager.hig.no.services.CardManagers;
import passwdmanager.hig.no.services.PasswdManager;

import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;

public class GUI implements CardListener {

	/**
	 * Reacts to inserted event.
	 */
	public void PasswdCardInserted(CardActionEvents ce) {
		System.out.println("Inserted passwd manager card.");
		long timeElapsed = 0;
		try {
			BasicService service = ce.getService();
			service.open();
			Reader reader = new Reader();
			if (service != null) {
				PasswdEnterDialog passwd = new PasswdEnterDialog(reader, "Passwd Manager Reader");
				timeElapsed = System.currentTimeMillis();
				byte[] s = passwd.getBACString();
				service.addAPDUListener(reader);
				if (s != null) {
					service.doBAC(s);
				}
				reader.setVisible(true);
				if (s != null) {
					reader.getStatusBar().setBACOK();
				} else {
					reader.getStatusBar().setBACNotChecked();
				}
				reader.setPasswdManager(new PasswdManager(service));
				if (reader.getPasswdManager().hasEAC()) {
					if (reader.getPasswdManager().wasEACPerformed()) {
						reader.getStatusBar().setEACOK();
					} else {
						reader.getStatusBar().setEACFail("TODO get reason");
					}
				} else {
					reader.getStatusBar().setEACNotChecked();
				}
				// Make the frame visible only after a successful BAC
				if (reader.getCOMFile() == null) {
					InputStream in = reader.getPasswdManager()
							.getInputStream(BasicService.EF_COM);
					reader.setCOMFile(new DG_COM(in));
					reader.readData();
					reader.verifySecurity(service);
				}
				timeElapsed = System.currentTimeMillis() - timeElapsed;
				System.out.println("Reading time: " + (timeElapsed / 1000) + " s.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Reacts to passwd manager removed event.
	 */
	public void PasswdCardRemoved(CardActionEvents ce) {
		System.out.println("Removed passwd manager card.");
	}

	/**
	 * Reacts to card inserted event.
	 */
	public void cardInserted(CardEvent ce) {
		System.out.println("Inserted card.");
	}

	/**
	 * Reacts to card removed event.
	 */
	public void cardRemoved(CardEvent ce) {
		System.out.println("Removed card.");
	}

	// Build the GUI and start up the application
	public static void main(String[] args) {
		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Locale.setDefault(Locale.ENGLISH);

		CardManagers manager = CardManagers.getInstance();
		manager.addPasswdManagerListener(new GUI());
		CardManager cm = CardManager.getInstance();
		for (CardTerminal t : cm.getTerminals()) {
			cm.startPolling(t);
		}
	}

}
