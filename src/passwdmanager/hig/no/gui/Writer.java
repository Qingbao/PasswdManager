package passwdmanager.hig.no.gui;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.Locale;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import net.sourceforge.scuba.smartcards.APDUEvent;
import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;
import net.sourceforge.scuba.util.Hex;
import passwdmanager.hig.no.events.CardActionEvents;
import passwdmanager.hig.no.lds.DG_1_FILE;
import passwdmanager.hig.no.lds.DG_2_FILE;
import passwdmanager.hig.no.lds.DG_3_FILE;
import passwdmanager.hig.no.lds.DG_COM;
import passwdmanager.hig.no.lds.DG_SOD;
import passwdmanager.hig.no.lds.DocumentSigner;
import passwdmanager.hig.no.lds.SecurityObjectIndicator;
import passwdmanager.hig.no.lds.SecurityObjectIndicatorDG14;
import passwdmanager.hig.no.lds.SimpleDocumentSigner;
import passwdmanager.hig.no.services.BasicInfo;
import passwdmanager.hig.no.services.BasicService;
import passwdmanager.hig.no.services.CardListener;
import passwdmanager.hig.no.services.CardManagers;
import passwdmanager.hig.no.services.PasswdManager;
import passwdmanager.hig.no.services.PersoService;
import passwdmanager.hig.no.utils.Files;
import passwdmanager.hig.no.utils.GUIutil;

import javax.smartcardio.*;

import org.ejbca.cvc.CVCertificate;

/**
 * A simple GUI application for creating password manager ID
 *
 * @author Qingbao Guo
 */
public class Writer extends JFrame implements ActionListener, APDUListener,
		ChangeListener, CardListener {

	// Constants for input event handling:
	private static final String LOADCERT = "loadcert";

	private static final String CLEARCERT = "clearcert";

	private static final String VIEWCERT = "viewcert";

	private static final String LOADCVCERT = "loadcvcert";

	private static final String CLEARCVCERT = "clearcvcert";

	private static final String VIEWCVCERT = "viewcvcert";

	private static final String LOADKEY = "loadkey";

	private static final String CLEARKEY = "clearkey";

	private static final String VIEWKEY = "viewkey";

	private static final String NONE = "<NONE>";

	private DataPanel DataPanel = null;

	private JTabbedPane picturesPane = null;

	private PicturePane fingerprint = null;

	private JTextField cert;

	private X509Certificate certificate = null;

	private JTextField cvCert;

	private CVCertificate cvCertificate = null;

	private JTextField key;

	private RSAPrivateKey privateKey = null;

	private JTextField keyseed;
	private JCheckBox bacSHA1;

	private JCheckBox eacDG3;

	private boolean debug = true;

	private JMenuBar menubar;
	private JMenu filemenu, helpmenu, uploadmenu;
	private JMenuItem exitItem, aboutItem, openItem, saveItem, uploadItem;

	private PersoService persoService = null;

	private PasswdManager passwdManager = null;

	/**
	 * Log the exchanged APDU-s on the console
	 */
	public void exchangedAPDU(APDUEvent apduEvent) {
		CommandAPDU c = apduEvent.getCommandAPDU();
		ResponseAPDU r = apduEvent.getResponseAPDU();
		if (debug) {
			System.out.println("C: " + Hex.bytesToHexString(c.getBytes()));
			System.out.println("R: " + Hex.bytesToHexString(r.getBytes()));
		}
	}

	/**
	 * Construct the main GUI frame.
	 *
	 */
	public Writer() {
		super("Password Manager ID Maker");
		setLayout(new BorderLayout());
		JTabbedPane tabbedPane = new JTabbedPane();

		Vector<InputField> inputs = new Vector<InputField>();

		inputs.add(new InputField("id", "Personnal number", new FieldFormat(
				FieldFormat.DIGITS, 11, 11), FieldGroup.Data));
		inputs.add(new InputField("web1", "Website 1", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 65), FieldGroup.Data));
		inputs.add(new InputField("web2", "Website 2", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 65), FieldGroup.Data));
		inputs.add(new InputField("web3", "Website 3", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 65), FieldGroup.Data));
		inputs.add(new InputField("web4", "Website 4", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 65), FieldGroup.Data));

		inputs.add(new InputField("emtry", "For future use", new FieldFormat(
				FieldFormat.SYMBOL | FieldFormat.LETTERS | FieldFormat.DIGITS,
				0, 25), FieldGroup.extraData));

		InputField[] ins = new InputField[inputs.size()];
		int i = 0;
		Iterator<InputField> it = inputs.iterator();
		while (it.hasNext()) {
			ins[i++] = it.next();
		}

		DataPanel = new DataPanel(this, ins, true);

		// One picture
		picturesPane = new JTabbedPane();
		fingerprint = new PicturePane("DG2", true);
		picturesPane.add(fingerprint.getTitle(), fingerprint);

		JPanel picPanel = new JPanel();
		picPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 2;
		c.fill = GridBagConstraints.HORIZONTAL;
		picPanel.add(picturesPane, c);
		c.insets = new Insets(5, 5, 5, 5);
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
		c.gridwidth = 1;
		c.gridy++;

		JPanel Panel = new JPanel();
		Panel.setLayout(new GridBagLayout());
		GridBagConstraints ccc = new GridBagConstraints();
		ccc.anchor = GridBagConstraints.NORTH;
		ccc.gridx = 0;
		ccc.gridy = 0;
		Panel.add(picPanel, ccc);
		ccc.gridx++;
		Panel.add(DataPanel, ccc);

		tabbedPane.add("Data", Panel);

		// Security things:
		JPanel certPanel = new JPanel();
		certPanel.setLayout(new GridBagLayout());
		c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.insets = new Insets(5, 5, 5, 5);
		c.anchor = GridBagConstraints.EAST;
		certPanel.add(new JLabel("Certificate: "), c);
		c.anchor = GridBagConstraints.WEST;
		c.gridx++;
		cert = new JTextField(10);
		cert.setText(NONE);
		cert.setEditable(false);
		certPanel.add(cert, c);

		c.gridx++;
		JButton button = new JButton("Load...");
		button.setActionCommand(LOADCERT);
		button.addActionListener(this);
		certPanel.add(button, c);

		c.gridx++;
		button = new JButton("Clear");
		button.setActionCommand(CLEARCERT);
		button.addActionListener(this);
		certPanel.add(button, c);

		c.gridx++;
		button = new JButton("View...");
		button.setActionCommand(VIEWCERT);
		button.addActionListener(this);
		certPanel.add(button, c);

		c.gridx = 0;
		c.gridy = 1;

		c.anchor = GridBagConstraints.EAST;
		certPanel.add(new JLabel("Key: "), c);
		c.anchor = GridBagConstraints.WEST;
		c.gridx++;
		key = new JTextField(10);
		key.setText(NONE);
		key.setEditable(false);
		certPanel.add(key, c);

		c.gridx++;
		button = new JButton("Load...");
		button.setActionCommand(LOADKEY);
		button.addActionListener(this);
		certPanel.add(button, c);

		c.gridx++;
		button = new JButton("Clear");
		button.setActionCommand(CLEARKEY);
		button.addActionListener(this);
		certPanel.add(button, c);

		c.gridx++;
		button = new JButton("View...");
		button.setActionCommand(VIEWKEY);
		button.addActionListener(this);
		certPanel.add(button, c);

		certPanel.setBorder(BorderFactory
				.createTitledBorder("Document Signature"));

		JPanel eacPanel = new JPanel();
		eacPanel.setLayout(new GridBagLayout());
		c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.insets = new Insets(5, 5, 5, 5);
		c.anchor = GridBagConstraints.EAST;
		eacPanel.add(new JLabel("Terminal cert: "), c);
		c.anchor = GridBagConstraints.WEST;
		c.gridx++;
		cvCert = new JTextField(10);
		cvCert.setText(NONE);
		cvCert.setEditable(false);
		eacPanel.add(cvCert, c);

		c.gridx++;
		button = new JButton("Load...");
		button.setActionCommand(LOADCVCERT);
		button.addActionListener(this);
		eacPanel.add(button, c);

		c.gridx++;
		button = new JButton("Clear");
		button.setActionCommand(CLEARCVCERT);
		button.addActionListener(this);
		eacPanel.add(button, c);

		c.gridx++;
		button = new JButton("View...");
		button.setActionCommand(VIEWCVCERT);
		button.addActionListener(this);
		eacPanel.add(button, c);

		c.gridx = 0;
		c.gridy++;
		c.gridwidth = 2;
		GridBagConstraints cc = new GridBagConstraints();
		cc.insets = new Insets(2, 2, 2, 2);
		JPanel checkBoxes = new JPanel();
		checkBoxes.setLayout(new GridBagLayout());
		eacDG3 = new JCheckBox("DG3", false);
		eacDG3.setEnabled(false);
		checkBoxes.add(eacDG3, cc);

		eacPanel.add(checkBoxes, c);
		eacPanel.setBorder(BorderFactory.createTitledBorder("EAC"));

		JPanel bacPanel = new JPanel();
		bacPanel.setLayout(new GridBagLayout());
		c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.insets = new Insets(5, 5, 5, 5);
		c.anchor = GridBagConstraints.EAST;
		bacPanel.add(new JLabel("Password: "), c);
		c.anchor = GridBagConstraints.WEST;
		c.gridx++;
		keyseed = new JTextField(20);
		keyseed.setText("");
		keyseed.setEditable(true);
		bacPanel.add(keyseed, c);

		c.gridx++;

		bacSHA1 = new JCheckBox(" SHA1", true);
		bacSHA1.setEnabled(false);
		bacPanel.add(bacSHA1);

		bacPanel.setBorder(BorderFactory.createTitledBorder("BAC"));

		JPanel secPanel = new JPanel();
		secPanel.setLayout(new GridBagLayout());
		c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(5, 5, 5, 5);
		secPanel.add(bacPanel, c);
		c.gridy++;
		secPanel.add(certPanel, c);
		c.gridy++;
		secPanel.add(eacPanel, c);

		tabbedPane.add("Security", secPanel);

		add(tabbedPane, BorderLayout.CENTER);

		// add menu bar
		menubar = new JMenuBar();
		filemenu = new JMenu("File");
		helpmenu = new JMenu("Help");
		uploadmenu = new JMenu("Upload");

		exitItem = new JMenuItem("Exit");
		openItem = new JMenuItem("Open zipfile");
		saveItem = new JMenuItem("Save zipfile");
		aboutItem = new JMenuItem("About..");
		uploadItem = new JMenuItem("upload");
		uploadItem.setEnabled(false);

		// add listener
		exitItem.addActionListener(this);
		exitItem.setActionCommand("exit");
		aboutItem.addActionListener(this);
		aboutItem.setActionCommand("about");
		openItem.addActionListener(this);
		openItem.setActionCommand("open");
		saveItem.addActionListener(this);
		saveItem.setActionCommand("save");
		uploadItem.addActionListener(this);
		uploadItem.setActionCommand("upload");
		// add to layout
		filemenu.add(openItem);
		filemenu.add(saveItem);
		filemenu.add(exitItem);
		helpmenu.add(aboutItem);
		uploadmenu.add(uploadItem);
		menubar.add(filemenu);
		menubar.add(uploadmenu);
		menubar.add(helpmenu);
		// setttings
		this.setJMenuBar(menubar);
		this.setFont(new Font("Times New Roman", Font.PLAIN, 12));

		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLocation(500, 100);
		setSize(800, 700); // set frame size
		setVisible(true);

		try {
			passwdManager = new PasswdManager();
		} catch (Exception e) {
			e.printStackTrace();
			JOptionPane.showMessageDialog(
					this,
					"Could not create an empty card, will exit. ("
					+ e.getClass() + ")");
			System.exit(1);
		}

	}

	private void processData() {
		picturesPane.removeAll();
		List<Short> files = passwdManager.getFileList();
		InputStream in = null;
		Short fid = null;
		try {
			fid = BasicService.EF_DG1;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				DG_1_FILE dg1file = new DG_1_FILE(in);
				BasicInfo bi = dg1file.getInfo();
				DataPanel.setValue("id", bi.id);
				DataPanel.setValue("web1", bi.web1);
				DataPanel.setValue("web2", bi.web2);
				DataPanel.setValue("web3", bi.web3);
				DataPanel.setValue("web4", bi.web4);
				files.remove(fid);
			}
			fid = BasicService.EF_DG2;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				DG_2_FILE dg2file = new DG_2_FILE(in);
				addPicture("DG2", dg2file.getImage(), dg2file.getMimeType(),
						null);
				files.remove(fid);
			}
			fid = BasicService.EF_DG3;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				DG_3_FILE dg3file = new DG_3_FILE(in);
				DataPanel.setValue("emtry", dg3file.emtry);
				files.remove(fid);
			}
			fid = BasicService.EF_DG15;
			if (files.contains(fid)) {
				files.remove(fid);
			}
			fid = BasicService.EF_DG14;
			if (files.contains(fid)) {
				files.remove(fid);
			}
			fid = BasicService.EF_SOD;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				DG_SOD sodFile = new DG_SOD(in);
				certificate = sodFile.getDocSigningCertificate();
				cert.setText(certificate.getIssuerDN().getName());
				files.remove(fid);
			}
			fid = BasicService.EF_COM;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				DG_COM comFile = new DG_COM(in);
				files.remove(fid);
				for (SecurityObjectIndicator soi : comFile.getSOIArray()) {
					if (soi instanceof SecurityObjectIndicatorDG14) {
						List<Integer> dgs = ((SecurityObjectIndicatorDG14) soi)
								.getDataGroups();
						cvCertificate = passwdManager.getCVCertificate();
						if (cvCertificate != null) {
							eacDG3.setEnabled(true);
							eacDG3.setSelected(dgs.contains(3));
							cvCert.setText(cvCertificate.getCertificateBody()
									.getHolderReference().getConcatenated());
						}

					}
				}
			}
			// See if there are any files that we did not know
			// how to handle:
			for (Short f : files) {
				System.out.println("Don't know how to handle file ID: "
						+ Hex.shortToHexString(f));
			}
			if (passwdManager.getKeySeed() != null) {
				keyseed.setText(new String(passwdManager.getKeySeed()));
				bacSHA1.setSelected(false);
			}
		} catch (Exception ioe) {
			ioe.printStackTrace();
		}
	}

	private void collectData() {

		BasicInfo bi = new BasicInfo(DataPanel.getValue("id"),
				DataPanel.getValue("web1"), DataPanel.getValue("web2"),
				DataPanel.getValue("web3"), DataPanel.getValue("web4"));

		passwdManager.putFile(BasicService.EF_DG1,
				new DG_1_FILE(bi).getEncoded());

		if (DataPanel.getValue("emtry") != null) {
			try {
				String emtry = DataPanel.getValue("emtry");
				passwdManager.putFile(BasicService.EF_DG3,
						new DG_3_FILE(emtry).getEncoded(), eacDG3.isEnabled()
						&& eacDG3.isSelected());
			} catch (NumberFormatException nfe) {
				nfe.printStackTrace();
			}
		}

		if (fingerprint.getImage() != null) {
			passwdManager.putFile(BasicService.EF_DG2, new DG_2_FILE(
					fingerprint.getImage(), fingerprint.getMimeType())
					.getEncoded());
		}

		try {
			Provider provider = Security.getProvider("BC");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
					provider);
			generator.initialize(new RSAKeyGenParameterSpec(1024,
					RSAKeyGenParameterSpec.F4));
			passwdManager.setAAKeys(generator.generateKeyPair());
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalStateException(
					"Could not generate RSA keys for AA.");
		}

		if (cvCertificate != null) {

			// Generate EC key pair for Extended Access Control
			KeyPair ecKeyPair = null;
			try {
				String preferredProvider = "BC";
				Provider provider = Security.getProvider(preferredProvider);
				KeyPairGenerator generator = KeyPairGenerator.getInstance(
						"ECDH", provider);
				generator.initialize(new ECGenParameterSpec(
						PersoService.EC_CURVE_NAME));
				ecKeyPair = generator.generateKeyPair();
				passwdManager.setEACKeys(ecKeyPair);
				passwdManager.setCVCertificate(cvCertificate);
			} catch (Exception e) {
				e.printStackTrace();
				throw new IllegalStateException(
						"Could not generate EC keys for EAC.");
			}
		}
		if (certificate != null) {
			passwdManager.setDocSigningCertificate(certificate);
		}
		if (privateKey != null) {
			DocumentSigner signer = new SimpleDocumentSigner(privateKey);
			if (certificate != null) {
				signer.setCertificate(certificate);
			}
			passwdManager.setSigner(signer);
		}
		byte[] ks = getKeySeed();
		if (ks != null) {
			passwdManager.setKeySeed(ks);
		}
	}

	/**
	 * Upload the PasswdManager based on the data in the GUI. Note: there is
	 * very little checks done on the presence of the (possibly required) data.
	 *
	 */
	private void uploadPasswdManager() {
		collectData();
		try {
			long timeElapsed = System.currentTimeMillis();
			passwdManager.upload(persoService, getKeySeed());
			timeElapsed = System.currentTimeMillis() - timeElapsed;
			System.out.println("Uploading time: " + (timeElapsed / 1000)
					+ " s.");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void saveZipFile() {
		collectData();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser
				.setFileFilter(net.sourceforge.scuba.util.Files.ZIP_FILE_FILTER);
		int choice = fileChooser.showSaveDialog(getContentPane());
		switch (choice) {
			case JFileChooser.APPROVE_OPTION:
				try {
					File file = fileChooser.getSelectedFile();
					FileOutputStream fileOut = new FileOutputStream(file);
					ZipOutputStream zipOut = new ZipOutputStream(fileOut);
					for (short fid : passwdManager.getFileList()) {
						String eac = "";
						if (fid == BasicService.EF_DG3 && eacDG3.isSelected()) {
							eac = "eac";
						}
						String entryName = Hex.shortToHexString(fid) + eac + ".bin";
						InputStream dg = passwdManager.getInputStream(fid);
						zipOut.putNextEntry(new ZipEntry(entryName));
						int bytesRead;
						byte[] dgBytes = new byte[1024];
						while ((bytesRead = dg.read(dgBytes)) > 0) {
							zipOut.write(dgBytes, 0, bytesRead);
						}
						zipOut.closeEntry();
					}
					byte[] keySeed = passwdManager.getKeySeed();
					if (keySeed != null) {
						String entryName = "keyseed.bin";
						zipOut.putNextEntry(new ZipEntry(entryName));
						zipOut.write(keySeed);
						zipOut.closeEntry();
					}
					PrivateKey aaPrivateKey = passwdManager.getAAPrivateKey();
					if (aaPrivateKey != null) {
						String entryName = "aaprivatekey.der";
						zipOut.putNextEntry(new ZipEntry(entryName));
						zipOut.write(aaPrivateKey.getEncoded());
						zipOut.closeEntry();
					}
					PrivateKey caPrivateKey = passwdManager.getEACPrivateKey();
					if (caPrivateKey != null) {
						String entryName = "caprivatekey.der";
						zipOut.putNextEntry(new ZipEntry(entryName));
						zipOut.write(caPrivateKey.getEncoded());
						zipOut.closeEntry();
					}
					CVCertificate cvCert = passwdManager.getCVCertificate();
					if (cvCert != null) {
						String entryName = "cacert.cvcert";
						zipOut.putNextEntry(new ZipEntry(entryName));
						zipOut.write(cvCert.getDEREncoded());
						zipOut.closeEntry();
					}
					zipOut.finish();
					zipOut.close();
					fileOut.flush();
					fileOut.close();
					break;
				} catch (IOException e) {
					e.printStackTrace();
				}
			default:
				break;
		}
	}

	private void loadZipFile() {
		JFileChooser fileChooser = new JFileChooser();
		fileChooser
				.setFileFilter(net.sourceforge.scuba.util.Files.ZIP_FILE_FILTER);
		int choice = fileChooser.showOpenDialog(getContentPane());
		switch (choice) {
			case JFileChooser.APPROVE_OPTION:
				try {
					if (privateKey != null) {
						passwdManager = new PasswdManager(
								fileChooser.getSelectedFile(), true,
								new SimpleDocumentSigner(privateKey));
					} else {
						passwdManager = new PasswdManager(
								fileChooser.getSelectedFile());
					}
					processData();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			default:
				break;
		}
	}

	/**
	 * Handles input events.
	 */
	public void actionPerformed(ActionEvent e) {
		if ("exit".equals(e.getActionCommand())) {
			System.exit(0);
		} else if ("about".equals(e.getActionCommand())) {
			JOptionPane.showMessageDialog(this, "Password Manager v1.0.\n By Qingbao Guo");
		} else if ("open".equals(e.getActionCommand())) {
			loadZipFile();
		} else if ("save".equals(e.getActionCommand())) {
			saveZipFile();
		} else if ("upload".equals(e.getActionCommand())) {
			uploadPasswdManager();
		} else if (LOADCERT.equals(e.getActionCommand())) {
			loadCertificate();
		} else if (LOADCVCERT.equals(e.getActionCommand())) {
			loadCVCertificate();
		} else if (CLEARCERT.equals(e.getActionCommand())) {
			certificate = null;
			cert.setText(NONE);
		} else if (CLEARCVCERT.equals(e.getActionCommand())) {
			cvCertificate = null;
			updateEACBoxesState();
			cvCert.setText(NONE);
		} else if (LOADKEY.equals(e.getActionCommand())) {
			loadKey();
		} else if (CLEARKEY.equals(e.getActionCommand())) {
			privateKey = null;
			key.setText(NONE);
		} else if (VIEWCERT.equals(e.getActionCommand())) {
			if (certificate != null) {
				try {
					viewData(certificate.toString(), certificate.getEncoded());
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		} else if (VIEWCVCERT.equals(e.getActionCommand())) {
			if (cvCertificate != null) {
				try {
					viewData(cvCertificate.getAsText(),
							cvCertificate.getDEREncoded());
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		} else if (VIEWKEY.equals(e.getActionCommand())) {
			if (privateKey != null) {
				viewData(privateKey.toString(), privateKey.getEncoded());
			}
		}

	}

	private void viewData(String s, byte[] data) {
		List<byte[]> l = new ArrayList<byte[]>();
		l.add(data);
		new ViewWindow(this, "View", s, l);
	}

	private void loadCertificate() {
		File f = GUIutil.getFile(this, "Load Certificate", false);
		if (f == null) {
			return;
		}
		certificate = Files.readCertFromFile(f);
		if (certificate != null) {
			cert.setText(certificate.getIssuerDN().getName());
		}

	}

	private void loadCVCertificate() {
		try {
			File file = GUIutil.getFile(this, "Load CV Certificate", false);
			cvCertificate = Files.readCVCertificateFromFile(file);

			if (cvCertificate != null) {
				cvCert.setText(cvCertificate.getCertificateBody()
						.getHolderReference().getConcatenated());
			}
		} catch (Exception e) {
			cvCertificate = null;
			cert.setText(NONE);
			e.printStackTrace();
		}
		updateEACBoxesState();
	}

	private void loadKey() {
		File f = GUIutil.getFile(this, "Load Key", false);
		if (f == null) {
			return;
		}
		privateKey = (RSAPrivateKey) Files.readRSAPrivateKeyFromFile(f);
		if (privateKey != null) {
			key.setText(privateKey.getAlgorithm() + " "
					+ privateKey.getFormat());
		}
	}

	private void addPicture(String title, byte[] image, String mimeType,
			String date) {
		PicturePane picture = new PicturePane(title, image, mimeType, date,
				true);

		fingerprint = picture;

		picturesPane.addTab(title, picture);
	}

	private byte[] getKeySeed() {
		byte[] ks = null;

		if (bacSHA1.isSelected()) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA1");
				byte[] t = md.digest(keyseed.getText().getBytes());
				ks = new byte[16];
				System.arraycopy(t, 0, ks, 0, 16);
			} catch (NoSuchAlgorithmException nsae) {
			}
		} else if (keyseed.getText().length() == 16) {
			ks = keyseed.getText().getBytes();
		}
		return ks;
	}

	public void updateEACBoxesState() {
		if (cvCertificate == null) {
			eacDG3.setEnabled(false);
		} else {
			eacDG3.setEnabled(true);
			eacDG3.setSelected(true);
		}
	}

	public void stateChanged(ChangeEvent e) {
		updateEACBoxesState();
	}

	/**
	 * Build up the frame and start up the application.
	 *
	 * @param args should be none (ignored)
	 */
	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Locale.setDefault(Locale.ENGLISH);
		CardManagers manager = CardManagers.getInstance();
		manager.addPasswdManagerListener(new Writer());
		CardManager cm = CardManager.getInstance();
		for (CardTerminal t : cm.getTerminals()) {
			cm.startPolling(t);
		}
	}

	@Override
	public void cardInserted(CardEvent ce) {
		System.out.println("Inserted card.");

	}

	@Override
	public void cardRemoved(CardEvent ce) {
		System.out.println("Removed card.");

	}

	@Override
	public void PasswdCardInserted(CardActionEvents ce) {
		System.out.println("Inserted passwd card.");
		try {
			BasicService s = ce.getService();
			s.addAPDUListener(this);
			persoService = new PersoService(s);
			persoService.open();
		} catch (Exception e) {
			persoService = null;
		}
		if (persoService != null) {
			if (uploadItem != null) {
				uploadItem.setEnabled(true);
			}
		}

	}

	@Override
	public void PasswdCardRemoved(CardActionEvents ce) {
		System.out.println("Removed passwd card.");
		persoService = null;
		if (uploadItem != null) {
			uploadItem.setEnabled(false);
		}

	}

}
